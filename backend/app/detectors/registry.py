"""
CyberSage AI — Detector Registry & Threat Aggregator

Central orchestrator for the modular threat detection pipeline.

DESIGN:
- Evaluates ALL registered detectors against the incident telemetry.
- Selects the highest-confidence matching detector as the PRIMARY threat.
- Preserves all secondary detector results for multi-vector awareness.
- Pre-runs IOCExtractor once so all detectors share the same forensic artifact set.
- Builds an AggregatedDetectionContext used by TriageService to assemble the final
  IncidentTriageResponse with enriched fields (IOCs, MITRE, confidence).
"""

import logging
from dataclasses import dataclass, field

from app.detectors.base import BaseDetector, DetectionResult
from app.detectors.ioc_extractor import IOCExtractor
from app.detectors.brute_force import BruteForceDetector
from app.detectors.phishing import PhishingDetector
from app.detectors.malware import MalwarePersistenceDetector
from app.detectors.web_attack import WebAttackDetector
from app.detectors.cloud_iam import CloudIAMDetector
from app.detectors.active_directory import ActiveDirectoryDetector
from app.detectors.ransomware_exfiltration import RansomwareExfiltrationDetector
from app.schemas.incident import (
    ExtractedIOCs,
    FalsePositiveRisk,
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageRequest,
    MitreMapping,
)

logger = logging.getLogger("cybersage.detectors.registry")


@dataclass
class AggregatedDetectionContext:
    """
    Output of the DetectorRegistry evaluation pipeline.
    Contains all information needed by TriageService to assemble
    an enterprise-enriched IncidentTriageResponse.
    """
    iocs: ExtractedIOCs
    primary_result: DetectionResult
    all_results: list[DetectionResult] = field(default_factory=list)
    secondary_categories: list[str] = field(default_factory=list)
    aggregated_mitre_tactics: list[str] = field(default_factory=list)
    aggregated_mitre_techniques: list[str] = field(default_factory=list)
    total_detectors_triggered: int = 0


class DetectorRegistry:
    """
    Runs all registered threat detectors against incident telemetry and
    aggregates results into a rich detection context.

    Adding a new detector:
      1. Create detector class inheriting from BaseDetector.
      2. Import it here and add to self._detectors list.
      No other changes required.
    """

    def __init__(self):
        self._extractor = IOCExtractor()
        self._detectors: list[BaseDetector] = [
            # Priority order matters for summary display (most impactful first)
            RansomwareExfiltrationDetector(),
            ActiveDirectoryDetector(),
            CloudIAMDetector(),
            MalwarePersistenceDetector(),
            WebAttackDetector(),
            BruteForceDetector(),
            PhishingDetector(),
        ]

    def evaluate(self, request: IncidentTriageRequest) -> AggregatedDetectionContext:
        """
        Main evaluation pipeline:
        1. Extract all IOCs from combined telemetry text.
        2. Run all detectors (pre-filter with can_detect for speed).
        3. Select highest-confidence primary result.
        4. Aggregate MITRE tactics/techniques across all matches.
        5. Return AggregatedDetectionContext.
        """
        # Build combined text corpus for detection (lowercase for matching)
        combined_text = (
            f"{request.title} {request.description} {request.raw_logs}"
        ).lower()
        if request.source_ip:
            combined_text += f" {request.source_ip}"
        if request.affected_asset:
            combined_text += f" {request.affected_asset}"

        # Step 1: Extract IOCs (shared across all detectors)
        iocs = self._extractor.extract(combined_text)
        logger.info(
            f"IOC Extraction: {len(iocs.public_ips)} public IPs, "
            f"{len(iocs.private_ips)} private IPs, "
            f"{len(iocs.file_hashes)} hashes, "
            f"{len(iocs.urls)} URLs, "
            f"{len(iocs.cve_ids)} CVEs extracted."
        )

        # Step 2: Run all detectors
        triggered_results: list[DetectionResult] = []
        for detector in self._detectors:
            if not detector.can_detect(combined_text):
                continue
            try:
                result = detector.analyze(combined_text, iocs)
                if result.detected and result.confidence > 0.0:
                    triggered_results.append(result)
                    logger.info(
                        f"[{detector.name}] TRIGGERED — "
                        f"category={result.category.value}, "
                        f"confidence={result.confidence:.2f}, "
                        f"severity={result.severity.value}"
                    )
            except Exception as e:
                logger.warning(f"[{detector.name}] raised exception during analysis: {e}")

        # Step 3: Select primary result (highest confidence, or generic fallback)
        if triggered_results:
            primary = max(triggered_results, key=lambda r: r.confidence)
        else:
            primary = DetectionResult(
                detected=False,
                category=IncidentCategory.OTHER,
                severity=IncidentSeverity.MEDIUM,
                confidence=0.3,
                mitre_mapping=MitreMapping(tactics=["Unknown"], techniques=["Unknown"]),
                evidence=["No specific threat pattern matched. Manual analyst review recommended."],
                recommended_steps=[
                    "Collect additional telemetry — endpoint, network, and identity logs.",
                    "Correlate with SIEM for related alerts in the same timeframe.",
                    "Escalate to tier-2 analyst for manual investigation.",
                ],
                summary="Anomalous activity reported but did not match known attack patterns.",
                false_positive_risk="HIGH",
            )

        # Step 4: Aggregate MITRE tactics and techniques across ALL matches
        all_tactics: list[str] = []
        all_techniques: list[str] = []
        secondary_categories: list[str] = []
        for result in triggered_results:
            if result is not primary:
                secondary_categories.append(result.category.value)
            for tactic in result.mitre_mapping.tactics:
                if tactic not in all_tactics:
                    all_tactics.append(tactic)
            for technique in result.mitre_mapping.techniques:
                if technique not in all_techniques:
                    all_techniques.append(technique)

        logger.info(
            f"Registry evaluation complete — primary: {primary.category.value} "
            f"(confidence={primary.confidence:.2f}), "
            f"secondary: {secondary_categories}, "
            f"total detectors triggered: {len(triggered_results)}"
        )

        return AggregatedDetectionContext(
            iocs=iocs,
            primary_result=primary,
            all_results=triggered_results,
            secondary_categories=secondary_categories,
            aggregated_mitre_tactics=all_tactics,
            aggregated_mitre_techniques=all_techniques,
            total_detectors_triggered=len(triggered_results),
        )
