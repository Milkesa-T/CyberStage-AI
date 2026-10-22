# CyberSage AI — n8n Automation Workflows

This directory contains production-ready n8n workflow templates for automated security operations, alert notifications, and incident escalation.

---

## Included Workflows

### 1. `workflows/incident_alert_slack_email.json`
- **Trigger**: Inbound HTTP Webhook from CyberSage AI (`POST /webhook/cybersage-incident-webhook`).
- **Condition Check**: Evaluates whether `requires_immediate_escalation` is `true` (Severity `HIGH` or `CRITICAL`).
- **Actions**:
  1. Formats and sends a rich Markdown security alert into the `#soc-alerts` Slack channel.
  2. Dispatches an urgent email alert to the incident response distribution list (`incident-response-team@...`).

---

## How to Import & Activate in n8n

1. **Open n8n UI**: Navigate to your running n8n instance (e.g. `http://localhost:5678` or hosted cloud instance).
2. **Import Workflow**:
   - In the top-right menu, select **Workflows** > **Import from File...**
   - Select `n8n/workflows/incident_alert_slack_email.json`.
3. **Configure Webhook URL**:
   - Double-click the **CyberSage Incident Webhook** node.
   - Copy the "Production URL" (e.g., `https://your-n8n.app/webhook/cybersage-incident-webhook`).
4. **Connect CyberSage AI Backend**:
   - In your backend `.env` file, set:
     ```env
     N8N_WEBHOOK_URL=https://your-n8n.app/webhook/cybersage-incident-webhook
     N8N_WEBHOOK_BEARER_TOKEN=optional_secret_token_here
     ```
5. **Activate the Workflow**: Toggle the workflow switch to **Active**.

---

## Sample Inbound Webhook Payload

When an incident is triaged by CyberSage AI, the following structured JSON payload is posted to n8n:

```json
{
  "event_type": "cybersage.incident.triaged",
  "incident_id": "7f8b9c1d-4e5a-6b7c-8d9e-0f1a2b3c4d5e",
  "timestamp": "2026-10-22T14:40:30.781000+00:00",
  "severity": "HIGH",
  "category": "BRUTE_FORCE",
  "title": "SSH Brute Force from Unknown External IP",
  "affected_asset": "bastion-01",
  "source_ip": "198.51.100.44",
  "summary": "Detected brute-force credential attacks targeting bastion-01 originating from 198.51.100.44.",
  "supporting_evidence": [
    "High-frequency authentication anomalies identified in submitted telemetry.",
    "Source address 198.51.100.44 repeatedly initiated login sequences."
  ],
  "recommended_steps": [
    "Verify if any successful authentications occurred after the burst of failed attempts.",
    "Apply immediate rate-limiting or firewall drop rule for the offending source IP address.",
    "Enforce MFA and rotate compromised user credentials if successful login detected."
  ],
  "playbook_citations": [
    "PB-001 (SSH Brute Force and Credential Stuffing Response) - 2. Key Indicators of Compromise (IOCs)"
  ],
  "requires_immediate_escalation": true
}
```
