from fastapi import APIRouter, BackgroundTasks, status
from app.schemas.incident import (
    IncidentTriageRequest,
    IncidentTriageResponse,
)
from app.services.triage_service import get_triage_service
from app.services.n8n_dispatcher import get_n8n_dispatcher

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


@router.post(
    "/triage",
    response_model=IncidentTriageResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit security incident for AI triage assessment",
    description="Validates incident telemetry, retrieves relevant defensive playbooks via ChromaDB, returns structured triage evaluation, and optionally triggers n8n alert workflows.",
)
async def triage_incident(
    request: IncidentTriageRequest,
    background_tasks: BackgroundTasks,
) -> IncidentTriageResponse:
    """
    Triage incident endpoint.
    Orchestrates ChromaDB playbook retrieval, Gemini structured reasoning,
    and background n8n webhook notification dispatch.
    """
    service = get_triage_service()
    assessment = service.triage(request)

    # Trigger background n8n notification if configured
    dispatcher = get_n8n_dispatcher()
    if dispatcher.is_configured:
        background_tasks.add_task(dispatcher.dispatch, assessment, request)

    return assessment
