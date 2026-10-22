import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, status
from app.schemas.incident import (
    IncidentTriageRequest,
    IncidentTriageResponse,
    IncidentSeverity,
    IncidentCategory,
    SourceReference,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


@router.post(
    "/triage",
    response_model=IncidentTriageResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit security incident for AI triage assessment",
    description="Validates incident telemetry and returns an initial structured defensive triage evaluation.",
)
async def triage_incident(request: IncidentTriageRequest) -> IncidentTriageResponse:
    """
    Triage incident endpoint.
    In Stages 4-6, this endpoint orchestrates ChromaDB playbook retrieval and Gemini structured reasoning.
    """
    # Deterministic contract demonstration for Stage 3 validation testing
    # Will be replaced with RAG + Gemini pipeline in Stages 4-6
    sample_reference = SourceReference(
        playbook_id="PB-001-SSH-BRUTE",
        playbook_title="SSH Brute Force and Credential Stuffing Response",
        section="Triage & Initial Containment",
        similarity_score=0.92,
        excerpt="Examine auth.log for high frequency failed authentication attempts against single or multiple accounts."
    )

    return IncidentTriageResponse(
        incident_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        suggested_severity=IncidentSeverity.HIGH,
        incident_category=IncidentCategory.BRUTE_FORCE,
        summary=f"Automated preliminary assessment for: {request.title}",
        supporting_evidence=[
            f"Analyzed {len(request.raw_logs)} characters of raw log telemetry.",
            f"Target affected asset: {request.affected_asset or 'Unspecified asset'}",
            f"Source IP noted: {request.source_ip or 'No specific IP provided'}",
        ],
        uncertainty_limitations="Playbook retrieval and LLM inference engine will be activated in upcoming stages.",
        recommended_steps=[
            "Verify network reachability and isolate affected host if unauthorized access is confirmed.",
            "Inspect auth.log for successful logins immediately following failed bursts.",
            "Temporarily block malicious source IP at border firewall/security group.",
        ],
        source_references=[sample_reference],
    )
