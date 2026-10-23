"""
CyberSage AI — Enterprise SOC SLA Calculator

Calculates enterprise response Service Level Agreements (SLAs) for incident triage:
- MTTA (Mean Time to Acknowledge): Target window to review, validate, and assign incident.
- MTTR (Mean Time to Remediate): Target window to complete containment and mitigation.
- Escalation Pathways: Designates authorized technical and management leadership tiers.
- Regulatory Breach Clocks: Tracks mandatory statutory windows (e.g. GDPR 72-hour notice).

SLA TIERS ALIGNED WITH NIST SP 800-61r2 & SANS INCIDENT HANDLER GUIDELINES:
- CRITICAL: MTTA = 15 mins | MTTR = 60 mins  | Escalation: Tier-3 Senior SOC & CISO On-Call
- HIGH:     MTTA = 30 mins | MTTR = 4 hours  | Escalation: Tier-2/3 Lead Analyst & Incident Commander
- MEDIUM:   MTTA = 2 hours | MTTR = 24 hours | Escalation: Tier-2 SOC Analyst
- LOW:      MTTA = 8 hours | MTTR = 72 hours | Escalation: Standard SOC Ticket Queue
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from app.schemas.incident import (
    IncidentCategory,
    IncidentSeverity,
    SLADeadline,
)


class SLACalculator:
    """
    Computes enterprise SOC response SLAs and regulatory notification countdowns.
    """

    _SLA_POLICY = {
        IncidentSeverity.CRITICAL: {
            "mtta_minutes": 15,
            "mttr_minutes": 60,
            "escalation": "Tier-3 Senior SOC, Incident Commander & CISO On-Call (Immediate PagerDuty Page)",
        },
        IncidentSeverity.HIGH: {
            "mtta_minutes": 30,
            "mttr_minutes": 240,  # 4 hours
            "escalation": "Tier-2/3 Lead SOC Analyst & Incident Commander",
        },
        IncidentSeverity.MEDIUM: {
            "mtta_minutes": 120,  # 2 hours
            "mttr_minutes": 1440,  # 24 hours
            "escalation": "Tier-2 SOC Analyst Team",
        },
        IncidentSeverity.LOW: {
            "mtta_minutes": 480,  # 8 hours
            "mttr_minutes": 4320,  # 72 hours
            "escalation": "Standard SOC Ticket Queue (Next Business Day)",
        },
    }

    def calculate(
        self,
        severity: IncidentSeverity,
        category: IncidentCategory,
        incident_time: Optional[datetime] = None,
    ) -> SLADeadline:
        """
        Calculate MTTA and MTTR deadlines relative to the incident timestamp.
        """
        base_time = incident_time or datetime.now(timezone.utc)
        if base_time.tzinfo is None:
            base_time = base_time.replace(tzinfo=timezone.utc)

        policy = self._SLA_POLICY.get(
            severity, self._SLA_POLICY[IncidentSeverity.MEDIUM]
        )

        mtta = policy["mtta_minutes"]
        mttr = policy["mttr_minutes"]
        escalation = policy["escalation"]

        ack_deadline = base_time + timedelta(minutes=mtta)
        rem_deadline = base_time + timedelta(minutes=mttr)

        # Regulatory window check (GDPR Art. 33 72-hour notification clock)
        reg_window = None
        if (
            category in (IncidentCategory.RANSOMWARE, IncidentCategory.DATA_EXFILTRATION)
            or severity == IncidentSeverity.CRITICAL
        ):
            gdpr_deadline = base_time + timedelta(hours=72)
            reg_window = (
                f"GDPR Article 33 — 72-Hour Supervisory Authority notification clock active "
                f"(Hard deadline: {gdpr_deadline.strftime('%Y-%m-%d %H:%M:%S UTC')})."
            )

        return SLADeadline(
            mtta_minutes=mtta,
            mttr_minutes=mttr,
            acknowledge_deadline_utc=ack_deadline,
            remediate_deadline_utc=rem_deadline,
            escalation_tier=escalation,
            regulatory_breach_window=reg_window,
        )
