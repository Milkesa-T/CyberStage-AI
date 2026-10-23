"""
CyberSage AI — Brute Force Detector (MITRE T1110)

Detects credential brute-forcing and password spraying attacks across:
- SSH (sshd failed password patterns)
- RDP (Remote Desktop failed logon EventID 4625)
- Kerberos (pre-authentication failures)
- HTTP Basic Auth / web login spraying
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_BRUTE_KEYWORDS = [
    "failed password", "authentication failure", "invalid user",
    "too many authentication failures", "maximum authentication attempts",
    "ssh", "hydra", "medusa", "brute", "credential stuff",
    "password spray", "failed logon", "eventid 4625",
    "kerberos pre-authentication failed", "eventid 4771",
]

_SUCCESS_SIGNALS = [
    "accepted password", "accepted publickey",
    "session opened for user", "logon type 3",
    "eventid 4624",
]


class BruteForceDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "BruteForceDetector"

    def can_detect(self, combined_text: str) -> bool:
        return any(kw in combined_text for kw in _BRUTE_KEYWORDS)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        # Count matching keyword signals for confidence scoring
        matched = sum(1 for kw in _BRUTE_KEYWORDS if kw in combined_text)
        confidence = min(0.95, 0.4 + (matched * 0.08))

        # Escalate to CRITICAL if successful auth found after burst
        success_post_burst = any(s in combined_text for s in _SUCCESS_SIGNALS)
        severity = IncidentSeverity.CRITICAL if success_post_burst else IncidentSeverity.HIGH

        attacker_ip = iocs.public_ips[0] if iocs.public_ips else (
            iocs.private_ips[0] if iocs.private_ips else "unknown source"
        )

        evidence = [
            f"Repeated authentication failures detected — {matched} brute-force indicators matched in telemetry.",
            f"Originating IP address: {attacker_ip} ({'internal lateral movement' if iocs.private_ips and not iocs.public_ips else 'external WAN source'}).",
        ]
        if success_post_burst:
            evidence.append("⚠️ CRITICAL: Successful authentication event detected following burst of failures — compromise likely.")

        steps = [
            "Block the offending source IP at the network border firewall and host-level security group.",
            "Audit /var/log/auth.log or Windows Security Event Log for any successful logins following the burst.",
            "Disable or lock the targeted account immediately; enforce MFA re-enrollment.",
            "Review SIEM for repeated attempts against other accounts from same IP (password spraying).",
            "Enable account lockout policy and geo-restriction for internet-exposed services.",
        ]
        fp_risk = "LOW" if matched >= 4 else "MEDIUM"

        return DetectionResult(
            detected=True,
            category=IncidentCategory.BRUTE_FORCE,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Credential Access", "Initial Access"],
                techniques=["T1110: Brute Force", "T1110.001: Password Guessing",
                             "T1110.004: Credential Stuffing"],
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=(
                f"Brute-force credential attack detected targeting "
                f"{combined_text.split('for')[1].split()[0] if 'for' in combined_text else 'authentication service'} "
                f"from {attacker_ip}."
            ),
            false_positive_risk=fp_risk,
        )
