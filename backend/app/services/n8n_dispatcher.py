"""
CyberSage AI — n8n Automation Webhook Dispatcher

Dispatches structured incident triage alerts to external n8n workflow webhooks
for automated downstream notifications (e.g., Slack, Email, PagerDuty, Jira ticket creation).

DESIGN DECISIONS:
- Non-blocking / Async: Uses httpx.AsyncClient with a strict timeout (5s) so that
  downstream automation outages never block or fail the primary triage response.
- Bearer Auth Support: Sends Authorization header if N8N_WEBHOOK_BEARER_TOKEN is configured.
- Graceful Degradation: If no webhook URL is configured or delivery fails, logs a clear warning
  and returns a structured dispatch status without interrupting the incident triage API contract.
"""

import logging
from typing import Optional
import httpx

from app.config import settings
from app.schemas.incident import IncidentTriageResponse, IncidentTriageRequest

logger = logging.getLogger("cybersage.services.n8n")


class N8nDispatcher:
    """
    Handles payload formatting and delivery to configured n8n webhook endpoints.
    """

    def __init__(self, webhook_url: Optional[str] = None, bearer_token: Optional[str] = None):
        self.webhook_url = webhook_url if webhook_url is not None else settings.N8N_WEBHOOK_URL
        self.bearer_token = bearer_token if bearer_token is not None else settings.N8N_WEBHOOK_BEARER_TOKEN

    @property
    def is_configured(self) -> bool:
        """Returns True if a valid HTTP(S) webhook URL is configured."""
        return bool(self.webhook_url and self.webhook_url.strip().startswith(("http://", "https://")))

    def format_payload(
        self,
        assessment: IncidentTriageResponse,
        request: IncidentTriageRequest,
    ) -> dict:
        """
        Builds a normalized JSON payload optimized for n8n workflow triggers.
        """
        return {
            "event_type": "cybersage.incident.triaged",
            "incident_id": assessment.incident_id,
            "timestamp": assessment.timestamp.isoformat(),
            "severity": assessment.suggested_severity.value,
            "category": assessment.incident_category.value,
            "title": request.title,
            "affected_asset": request.affected_asset or "Unknown",
            "source_ip": request.source_ip or "Unknown",
            "summary": assessment.summary,
            "supporting_evidence": assessment.supporting_evidence,
            "recommended_steps": assessment.recommended_steps,
            "playbook_citations": [
                f"{ref.playbook_id} ({ref.playbook_title}) - {ref.section}"
                for ref in assessment.source_references
            ],
            "requires_immediate_escalation": assessment.suggested_severity.value in ["HIGH", "CRITICAL"],
        }

    async def dispatch(
        self,
        assessment: IncidentTriageResponse,
        request: IncidentTriageRequest,
    ) -> dict:
        """
        Asynchronously sends the incident triage payload to the configured n8n webhook.
        Returns a delivery status dict.
        """
        if not self.is_configured:
            logger.debug("n8n webhook URL not configured; skipping automated dispatch.")
            return {
                "dispatched": False,
                "reason": "N8N_WEBHOOK_URL_NOT_CONFIGURED",
                "status_code": None,
            }

        payload = self.format_payload(assessment, request)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"CyberSage-AI/{settings.APP_VERSION}",
        }
        if self.bearer_token and self.bearer_token.strip():
            headers["Authorization"] = f"Bearer {self.bearer_token.strip()}"

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
                )
                logger.info(
                    f"Dispatched incident {assessment.incident_id} to n8n webhook: HTTP {response.status_code}"
                )
                return {
                    "dispatched": response.is_success,
                    "status_code": response.status_code,
                    "reason": "OK" if response.is_success else f"HTTP_{response.status_code}",
                }
        except httpx.TimeoutException:
            logger.warning(f"Timeout delivering incident {assessment.incident_id} to n8n at {self.webhook_url}")
            return {"dispatched": False, "status_code": None, "reason": "TIMEOUT"}
        except Exception as e:
            logger.warning(f"Failed to dispatch incident {assessment.incident_id} to n8n: {e}")
            return {"dispatched": False, "status_code": None, "reason": f"ERROR: {str(e)}"}


_dispatcher: Optional[N8nDispatcher] = None


def get_n8n_dispatcher() -> N8nDispatcher:
    """Returns the singleton N8nDispatcher instance."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = N8nDispatcher()
    return _dispatcher
