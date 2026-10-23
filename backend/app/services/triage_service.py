"""
CyberSage AI — Defensive Incident Triage Service

Orchestrates the end-to-end incident triage lifecycle:
1. Detector Registry: Runs all modular threat detectors & IOC extraction against raw telemetry.
2. Retrieval: Queries ChromaDB vector store for relevant defensive playbooks.
3. Prompt Formulation: Synthesizes alert metadata, bounded logs, and playbook context with guardrails.
4. LLM Inference: Invokes Google Gemini 2.5 Flash with structured output and low temperature.
5. Fallback Handling: In offline or unauthenticated environments (missing GEMINI_API_KEY),
   engages a defensive heuristic rule engine so tests, pipelines, and local dev function deterministically.
6. Enterprise Enrichment:
   - Phase 1: IOC Extraction & Defanging, MITRE ATT&CK Attribution, Confidence Score, False Positive Risk.
   - Phase 2: Regulatory Compliance Controls (NIST, ISO 27001, SOC 2, PCI-DSS, HIPAA, GDPR),
     Enterprise SOC Response SLAs (MTTA / MTTR), and Executable Remediation Shell Scripts.
7. Response Assembly: Validates and serializes into complete IncidentTriageResponse.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from google import genai
from google.genai import types

from app.compliance.mapper import ComplianceMapper
from app.compliance.sla import SLACalculator
from app.config import settings
from app.core.prompts import TRIAGE_SYSTEM_INSTRUCTION, build_triage_prompt
from app.detectors.registry import AggregatedDetectionContext, DetectorRegistry
from app.rag.store import get_store
from app.remediation.generator import RemediationGenerator
from app.schemas.incident import (
    ComplianceRequirement,
    ExtractedIOCs,
    FalsePositiveRisk,
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageRequest,
    IncidentTriageResponse,
    MitreMapping,
    RemediationScript,
    SLADeadline,
    SourceReference,
)

logger = logging.getLogger("cybersage.services.triage")


class TriageService:
    """
    Defensive incident triage orchestrator combining modular detection, RAG retrieval,
    regulatory compliance mapping, SOC SLA deadlines, and Gemini intelligence.
    """

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.GEMINI_API_KEY
        self.model_name = model_name or settings.GEMINI_MODEL
        self._gemini_client: Optional[genai.Client] = None
        self._detector_registry = DetectorRegistry()
        self._compliance_mapper = ComplianceMapper()
        self._sla_calculator = SLACalculator()
        self._remediation_generator = RemediationGenerator()

        if self.api_key and self.api_key.strip() and self.api_key != "your_gemini_api_key_here":
            try:
                self._gemini_client = genai.Client(api_key=self.api_key)
                logger.info(f"Gemini Client initialized for model '{self.model_name}'")
            except Exception as e:
                logger.warning(f"Could not initialize Gemini Client: {e}. Falling back to heuristic mode.")
        else:
            logger.info("No valid GEMINI_API_KEY detected. TriageService will operate in heuristic mode.")

    def _retrieve_playbooks(self, request: IncidentTriageRequest, top_k: int = 3) -> list[dict]:
        """
        Query ChromaDB for playbook chunks matching the incident title and description.
        Returns a list of dicts with playbook metadata and text excerpts.
        """
        try:
            try:
                store = get_store()
            except RuntimeError:
                from app.rag.store import initialize_store
                from app.rag.parser import parse_all_playbooks
                store = initialize_store(
                    persist_directory=settings.resolved_chroma_dir,
                    embedding_model=settings.EMBEDDING_MODEL_NAME,
                )
                if store.is_empty():
                    chunks = parse_all_playbooks(settings.resolved_playbooks_dir)
                    if chunks:
                        store.ingest(chunks)

            query_str = f"{request.title} {request.description}"
            return store.query(query_text=query_str, n_results=top_k)
        except Exception as e:
            logger.warning(f"ChromaDB retrieval unavailable: {e}. Proceeding without RAG context.")
            return []

    def _call_gemini(self, prompt: str) -> dict:
        """
        Invoke Gemini via google-genai SDK requesting structured JSON output.
        """
        if not self._gemini_client:
            raise RuntimeError("Gemini client is not initialized")

        config = types.GenerateContentConfig(
            system_instruction=TRIAGE_SYSTEM_INSTRUCTION,
            temperature=0.1,
            response_mime_type="application/json",
        )

        response = self._gemini_client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=config,
        )

        text_content = response.text or "{}"
        # Strip potential markdown wrapping if returned despite response_mime_type
        cleaned = re.sub(r"^```(?:json)?\s*", "", text_content.strip())
        cleaned = re.sub(r"\s*```$", "", cleaned.strip())

        return json.loads(cleaned)

    def _heuristic_triage(
        self,
        request: IncidentTriageRequest,
        retrieved_playbooks: list[dict],
        detection_ctx: AggregatedDetectionContext,
    ) -> dict:
        """
        Deterministic, rule-based triage assessment.
        Uses primary DetectionResult from the registry when a detector triggers.
        """
        primary = detection_ctx.primary_result

        if primary.detected and primary.confidence > 0.3:
            return {
                "suggested_severity": primary.severity,
                "incident_category": primary.category,
                "summary": primary.summary or f"Threat detected: {primary.category.value.replace('_', ' ').title()}",
                "supporting_evidence": primary.evidence,
                "uncertainty_limitations": (
                    "Triage generated via modular heuristic detector engine. "
                    "Provide a valid GEMINI_API_KEY to activate full Gemini 2.5 Flash neural reasoning."
                ),
                "recommended_steps": primary.recommended_steps,
            }

        # Legacy keyword fallback (no detector matched)
        combined_text = f"{request.title} {request.description} {request.raw_logs}".lower()
        if any(w in combined_text for w in ["ssh", "failed password", "brute", "hydra", "stuffing"]):
            category = IncidentCategory.BRUTE_FORCE
            severity = IncidentSeverity.HIGH if "accepted password" in combined_text else IncidentSeverity.MEDIUM
            summary = (
                f"Detected brute-force credential attacks targeting {request.affected_asset or 'the target host'} "
                f"originating from {request.source_ip or 'external IP'}."
            )
            evidence = [
                "High-frequency authentication anomalies identified in submitted telemetry.",
                f"Source address {request.source_ip or 'unknown'} repeatedly initiated login sequences.",
                f"Target system: {request.affected_asset or 'unspecified host'}.",
            ]
            steps = [
                "Verify if any successful authentications occurred after the burst of failed attempts.",
                "Apply immediate rate-limiting or firewall drop rule for the offending source IP address.",
                "Enforce MFA and rotate compromised user credentials if successful login detected.",
            ]
        elif any(w in combined_text for w in ["phish", "invoice", "urgent", "dkim", "spf", "spoof"]):
            category = IncidentCategory.PHISHING
            severity = IncidentSeverity.HIGH
            summary = f"Suspected phishing or credential harvesting campaign reported: {request.title}."
            evidence = [
                "Email headers or message content exhibit indicators of domain spoofing or deceptive lure.",
                "Embedded links or attachments require sandbox detonating and URL reputation check.",
            ]
            steps = [
                "Quarantine the suspicious email across all organization mailboxes via M365/Google Workspace.",
                "Block malicious sender domain and target URL at perimeter web proxy and email gateway.",
                "Review identity logs for any recipients who clicked the link or submitted credentials.",
            ]
        elif any(w in combined_text for w in ["powershell", "persistence", "registry", "scheduled task", "cron", "beacon"]):
            category = IncidentCategory.MALWARE
            severity = IncidentSeverity.CRITICAL if "beacon" in combined_text else IncidentSeverity.HIGH
            summary = f"Malware execution or persistence mechanism detected on {request.affected_asset or 'endpoint'}."
            evidence = [
                "Telemetry indicates unauthorized script execution or suspicious persistence entry creation.",
                "Command-line arguments indicate defense evasion or payload staging activity.",
            ]
            steps = [
                "Immediately isolate the affected endpoint from the local network segment via EDR.",
                "Capture volatile system memory (RAM) and triage artifact image before host reboot.",
                "Inspect persistence locations (cron, scheduled tasks, registry run keys) and terminate rogue processes.",
            ]
        elif any(w in combined_text for w in ["iam", "aws", "access_key", "secret_key", "bucket", "exfiltration"]):
            category = IncidentCategory.CLOUD_INFRASTRUCTURE
            severity = IncidentSeverity.CRITICAL
            summary = f"Potential credential leak or unauthorized cloud identity activity: {request.title}."
            evidence = [
                "Cloud audit logs indicate API calls originating from anomalous geography or untrusted IP.",
                "High-privilege actions observed without expected operational ticket reference.",
            ]
            steps = [
                "Immediately deactivate the exposed cloud access keys or IAM session tokens.",
                "Attach an explicit deny-all boundary policy to the compromised IAM identity.",
                "Review CloudTrail / audit logs for the last 72 hours to evaluate data exfiltration scope.",
            ]
        else:
            category = IncidentCategory.OTHER
            severity = IncidentSeverity.MEDIUM
            summary = f"Preliminary security anomaly assessment for incident: {request.title}."
            evidence = [
                f"Analyzed {len(request.raw_logs)} characters of event log telemetry.",
                f"Reported asset: {request.affected_asset or 'General environment'}.",
            ]
            steps = [
                "Review correlated firewall, proxy, and endpoint logs for corresponding timestamps.",
                "Confirm whether activity correlates with authorized administrative maintenance.",
                "Conduct follow-up telemetry collection on the affected hosts.",
            ]

        return {
            "suggested_severity": severity,
            "incident_category": category,
            "summary": summary,
            "supporting_evidence": evidence,
            "uncertainty_limitations": (
                "Notice: Triage generated via deterministic defensive heuristic engine. "
                "Provide a valid GEMINI_API_KEY in backend configuration to activate full Gemini 2.5 Flash neural reasoning."
            ),
            "recommended_steps": steps,
        }

    def triage(self, request: IncidentTriageRequest) -> IncidentTriageResponse:
        """
        Executes end-to-end enterprise incident triage:
        detectors → RAG → LLM/heuristic → compliance mapping → SLA calculation → remediation generation.
        """
        logger.info(f"Initiating enterprise triage for incident: '{request.title}'")
        now_utc = datetime.now(timezone.utc)

        # 1. Run Modular Detector Registry (Phase 1)
        detection_ctx = self._detector_registry.evaluate(request)
        logger.info(
            f"Detection complete — primary: {detection_ctx.primary_result.category.value}, "
            f"confidence: {detection_ctx.primary_result.confidence:.2f}, "
            f"IOC count: {detection_ctx.iocs.ioc_count}"
        )

        # 2. RAG Retrieval
        retrieved_raw = self._retrieve_playbooks(request, top_k=3)
        source_refs: list[SourceReference] = []
        for item in retrieved_raw:
            source_refs.append(
                SourceReference(
                    playbook_id=item.get("playbook_id", "PB-UNKNOWN"),
                    playbook_title=item.get("playbook_title", "Unknown Playbook"),
                    section=item.get("section", "General"),
                    similarity_score=float(item.get("similarity_score", 0.0)),
                    excerpt=item.get("excerpt", "")[:400],
                )
            )

        # 3. Decision Engine (Gemini LLM or Heuristic Fallback)
        raw_assessment: dict
        if self._gemini_client:
            try:
                prompt = build_triage_prompt(
                    title=request.title,
                    description=request.description,
                    raw_logs=request.raw_logs,
                    source_ip=request.source_ip,
                    affected_asset=request.affected_asset,
                    retrieved_playbooks=retrieved_raw,
                )
                raw_assessment = self._call_gemini(prompt)
                logger.info("Successfully received structured assessment from Gemini model.")
            except Exception as e:
                logger.error(f"Gemini API invocation failed ({e}). Falling back to heuristic assessment.")
                raw_assessment = self._heuristic_triage(request, retrieved_raw, detection_ctx)
        else:
            raw_assessment = self._heuristic_triage(request, retrieved_raw, detection_ctx)

        # 4. Resolve Severity and Category
        severity_val = raw_assessment.get("suggested_severity", "MEDIUM")
        if isinstance(severity_val, IncidentSeverity):
            severity = severity_val
        else:
            try:
                severity = IncidentSeverity(str(severity_val).upper())
            except ValueError:
                severity = IncidentSeverity.MEDIUM

        category_val = raw_assessment.get("incident_category", "OTHER")
        if isinstance(category_val, IncidentCategory):
            category = category_val
        else:
            try:
                category = IncidentCategory(str(category_val).upper())
            except ValueError:
                category = IncidentCategory.OTHER

        # 5. MITRE Mapping & False Positive Risk (Phase 1)
        mitre = MitreMapping(
            tactics=detection_ctx.aggregated_mitre_tactics or detection_ctx.primary_result.mitre_mapping.tactics,
            techniques=detection_ctx.aggregated_mitre_techniques or detection_ctx.primary_result.mitre_mapping.techniques,
        )

        fp_risk_str = detection_ctx.primary_result.false_positive_risk
        try:
            fp_risk = FalsePositiveRisk(fp_risk_str.upper())
        except (ValueError, AttributeError):
            fp_risk = FalsePositiveRisk.MEDIUM

        # 6. Compliance Mapping, SLA Calculation & Remediation Scripts (Phase 2)
        compliance_reqs = self._compliance_mapper.map_compliance(
            category=category,
            severity=severity,
            iocs=detection_ctx.iocs,
        )

        sla_deadline = self._sla_calculator.calculate(
            severity=severity,
            category=category,
            incident_time=now_utc,
        )

        remediation_scripts = self._remediation_generator.generate(
            category=category,
            severity=severity,
            iocs=detection_ctx.iocs,
            affected_asset=request.affected_asset,
        )

        logger.info(
            f"Enterprise enrichment complete — {len(compliance_reqs)} compliance controls, "
            f"MTTA={sla_deadline.mtta_minutes}m, "
            f"{len(remediation_scripts)} remediation scripts generated."
        )

        return IncidentTriageResponse(
            incident_id=str(uuid.uuid4()),
            timestamp=now_utc,
            suggested_severity=severity,
            incident_category=category,
            summary=raw_assessment.get("summary", f"Triage assessment for {request.title}"),
            supporting_evidence=raw_assessment.get("supporting_evidence", []),
            uncertainty_limitations=raw_assessment.get(
                "uncertainty_limitations", "No specific limitations noted."
            ),
            recommended_steps=raw_assessment.get("recommended_steps", []),
            source_references=source_refs,
            # Phase 1 enrichment
            extracted_iocs=detection_ctx.iocs,
            mitre_mapping=mitre,
            confidence_score=round(detection_ctx.primary_result.confidence, 3),
            false_positive_risk=fp_risk,
            # Phase 2 enrichment
            compliance_mappings=compliance_reqs,
            sla_deadline=sla_deadline,
            remediation_scripts=remediation_scripts,
        )


# Singleton instance
_service: Optional[TriageService] = None


def get_triage_service() -> TriageService:
    """Returns the singleton TriageService instance."""
    global _service
    if _service is None:
        _service = TriageService()
    return _service
