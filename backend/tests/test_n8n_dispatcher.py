import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone
import httpx
from app.schemas.incident import (
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageRequest,
    IncidentTriageResponse,
    SourceReference,
)
from app.services.n8n_dispatcher import N8nDispatcher


@pytest.fixture
def sample_assessment():
    return IncidentTriageResponse(
        incident_id="test-incident-uuid-1234",
        timestamp=datetime.now(timezone.utc),
        suggested_severity=IncidentSeverity.CRITICAL,
        incident_category=IncidentCategory.MALWARE,
        summary="Critical ransomware infection detected.",
        supporting_evidence=["Shadow copies deleted via vssadmin"],
        uncertainty_limitations="Scope of propagation across subnet unconfirmed.",
        recommended_steps=["Isolate all domain machines immediately"],
        source_references=[
            SourceReference(
                playbook_id="PB-003-MALWARE",
                playbook_title="Malware Incident Response",
                section="Containment",
                similarity_score=0.89,
                excerpt="Network isolation is primary containment control.",
            )
        ],
    )


@pytest.fixture
def sample_request():
    return IncidentTriageRequest(
        title="Ransomware outbreak alert",
        description="Encrypted files detected on fileserver",
        raw_logs="vssadmin delete shadows /all /quiet",
        source_ip="10.10.10.5",
        affected_asset="fs-01",
    )


def test_n8n_dispatcher_unconfigured(sample_assessment, sample_request):
    dispatcher = N8nDispatcher(webhook_url="")
    assert not dispatcher.is_configured


def test_n8n_dispatcher_payload_formatting(sample_assessment, sample_request):
    dispatcher = N8nDispatcher(webhook_url="https://n8n.example.com/webhook/test")
    payload = dispatcher.format_payload(sample_assessment, sample_request)

    assert payload["event_type"] == "cybersage.incident.triaged"
    assert payload["incident_id"] == "test-incident-uuid-1234"
    assert payload["severity"] == "CRITICAL"
    assert payload["category"] == "MALWARE"
    assert payload["affected_asset"] == "fs-01"
    assert payload["source_ip"] == "10.10.10.5"
    assert payload["requires_immediate_escalation"] is True
    assert len(payload["playbook_citations"]) == 1


@pytest.mark.asyncio
async def test_n8n_dispatcher_success(sample_assessment, sample_request):
    webhook_url = "https://n8n.example.com/webhook/alert"
    dispatcher = N8nDispatcher(webhook_url=webhook_url, bearer_token="secret-token-xyz")

    mock_resp = httpx.Response(200, request=httpx.Request("POST", webhook_url))
    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        status = await dispatcher.dispatch(sample_assessment, sample_request)
        assert status["dispatched"] is True
        assert status["status_code"] == 200
        assert status["reason"] == "OK"
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_n8n_dispatcher_handles_http_error(sample_assessment, sample_request):
    webhook_url = "https://n8n.example.com/webhook/error"
    dispatcher = N8nDispatcher(webhook_url=webhook_url)

    mock_resp = httpx.Response(500, request=httpx.Request("POST", webhook_url))
    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        status = await dispatcher.dispatch(sample_assessment, sample_request)
        assert status["dispatched"] is False
        assert status["status_code"] == 500


@pytest.mark.asyncio
async def test_n8n_dispatcher_handles_timeout(sample_assessment, sample_request):
    webhook_url = "https://n8n.example.com/webhook/timeout"
    dispatcher = N8nDispatcher(webhook_url=webhook_url)

    with patch.object(httpx.AsyncClient, "post", side_effect=httpx.TimeoutException("Timeout")):
        status = await dispatcher.dispatch(sample_assessment, sample_request)
        assert status["dispatched"] is False
        assert status["reason"] == "TIMEOUT"
