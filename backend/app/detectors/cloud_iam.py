"""
CyberSage AI — Cloud IAM & Infrastructure Detector (MITRE T1078.004, T1552.005)

Detects cloud identity, credential, and infrastructure compromise events:
- AWS IAM access key exposure and anomalous API calls
- CloudTrail events showing privilege escalation (CreateRole, AttachPolicy)
- Security group misconfiguration (0.0.0.0/0 ingress on all ports)
- Azure / GCP credential events (service principals, OAuth tokens)
- AWS metadata service access via SSRF
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_CLOUD_KEYWORDS = [
    # AWS identifiers
    "akia", "aroa", "asia",  # AWS key prefixes
    "arn:aws", "cloudtrail",
    "authorizedsecuritygroupingress", "authorizesecuritygroupingress",
    "0.0.0.0/0", "::/0",
    "createaccesskey", "putrolepolicy", "attachrolepolicy",
    "assumerole", "createpolicy", "passrole",
    # Azure
    "azure", "service principal", "oauth token", "client secret",
    "arm.azure.com", "management.azure.com",
    # GCP
    "googleapis.com", "gcloud", "service_account",
    # General cloud compromise
    "metadata service", "imds", "instance metadata",
    "secret_access_key", "aws_access_key",
    "access_key_id", "aws_secret",
]

_CRITICAL_CLOUD_SIGNALS = [
    "0.0.0.0/0", "::/0",
    "createaccesskey", "putrolepolicy", "attachrolepolicy",
    "secret_access_key", "aws_secret",
]


class CloudIAMDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "CloudIAMDetector"

    def can_detect(self, combined_text: str) -> bool:
        return any(kw in combined_text for kw in _CLOUD_KEYWORDS)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        matched = sum(1 for kw in _CLOUD_KEYWORDS if kw in combined_text)
        critical_signals = sum(1 for s in _CRITICAL_CLOUD_SIGNALS if s in combined_text)
        has_cloud_key = bool(iocs.cloud_identities)
        confidence = min(0.97, 0.45 + (matched * 0.07) + (critical_signals * 0.10))
        severity = IncidentSeverity.CRITICAL if (critical_signals > 0 or has_cloud_key) else IncidentSeverity.HIGH

        evidence = [
            f"Cloud infrastructure/IAM compromise signals: {matched} indicators matched.",
        ]
        if iocs.cloud_identities:
            evidence.append(f"⚠️ Cloud identity artifacts extracted: {', '.join(iocs.cloud_identities[:3])}.")
        if "0.0.0.0/0" in combined_text or "::/0" in combined_text:
            evidence.append("⚠️ CRITICAL: Security group opened to ALL traffic (0.0.0.0/0) — immediate exposure to internet.")
        if any(p in combined_text for p in ["putrolepolicy", "attachrolepolicy", "createaccesskey"]):
            evidence.append("Privileged IAM operation detected — attacker may have escalated cloud permissions or created backdoor credentials.")

        steps = [
            "IMMEDIATELY deactivate the exposed AWS Access Key / Azure service principal via IAM console.",
            "Attach an explicit Deny-All boundary policy to the compromised IAM identity.",
            "Review CloudTrail / Azure Activity Logs for the past 72 hours for all actions taken under the compromised identity.",
            "Check for newly created IAM roles, policies, or access keys that could serve as backdoors.",
            "Revoke all active sessions and tokens associated with the compromised identity.",
            "Enable AWS CloudTrail Data Events and GuardDuty if not already active.",
        ]

        return DetectionResult(
            detected=True,
            category=IncidentCategory.CLOUD_INFRASTRUCTURE,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Credential Access", "Privilege Escalation", "Defense Evasion"],
                techniques=[
                    "T1078.004: Valid Accounts: Cloud Accounts",
                    "T1552.005: Cloud Instance Metadata API",
                    "T1098.001: Account Manipulation: Additional Cloud Credentials",
                ],
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=f"Cloud IAM or infrastructure compromise detected with {matched} behavioral indicators and {critical_signals} critical signals.",
            false_positive_risk="LOW" if critical_signals > 0 or has_cloud_key else "MEDIUM",
        )
