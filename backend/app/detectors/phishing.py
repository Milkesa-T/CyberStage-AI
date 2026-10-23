"""
CyberSage AI — Phishing & Social Engineering Detector (MITRE T1566)

Detects phishing, spear-phishing, and credential harvesting attacks via:
- Email header anomalies (SPF fail, DKIM none, DMARC fail)
- Lookalike domain names (typosquatting patterns)
- Urgent financial lures (wire transfers, invoices, password reset)
- Malicious embedded links and attachment indicators
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_PHISHING_KEYWORDS = [
    "spf=fail", "spf=softfail", "dkim=none", "dkim=fail",
    "dmarc=fail", "dmarc=none",
    "phish", "spear phish", "credential harvest",
    "wire transfer", "urgent invoice", "payment request",
    "password reset", "account suspension", "verify your account",
    "click here to login", "unusual activity detected",
    "suspicious login", "your account has been",
    "spoofed", "impersonat", "lookalike", "typosquat",
]

_HIGH_RISK_TERMS = [
    "wire transfer", "urgent invoice", "ceo fraud", "bec",
    "business email compromise", "credential", "harvest",
]


class PhishingDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "PhishingDetector"

    def can_detect(self, combined_text: str) -> bool:
        return any(kw in combined_text for kw in _PHISHING_KEYWORDS)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        matched = sum(1 for kw in _PHISHING_KEYWORDS if kw in combined_text)
        high_risk = any(t in combined_text for t in _HIGH_RISK_TERMS)
        confidence = min(0.92, 0.35 + (matched * 0.07))

        severity = IncidentSeverity.HIGH
        if high_risk and iocs.urls:
            severity = IncidentSeverity.CRITICAL

        auth_fail = "spf=fail" in combined_text or "dkim=fail" in combined_text or "dmarc=fail" in combined_text
        evidence = [
            f"Phishing/social-engineering indicators matched: {matched} rule(s) triggered.",
        ]
        if auth_fail:
            evidence.append("Email authentication validation failed (SPF/DKIM/DMARC) — message is NOT from claimed sender domain.")
        if iocs.urls:
            evidence.append(f"Embedded URLs detected: {', '.join(iocs.defanged_urls[:3])}.")
        if iocs.domains:
            evidence.append(f"Suspicious domains extracted: {', '.join(iocs.domains[:3])}.")

        steps = [
            "Quarantine the malicious email across ALL organization mailboxes immediately via M365/Google Workspace admin.",
            "Block sender domain and all extracted URLs at perimeter email gateway and web proxy.",
            "Query email gateway logs for any recipients who clicked links or opened attachments.",
            "Identify anyone who may have submitted credentials — force password reset and revoke active sessions.",
            "Submit samples to threat intelligence platform and update blocklists.",
            "Run security awareness training reminder for all recipients of the campaign.",
        ]

        return DetectionResult(
            detected=True,
            category=IncidentCategory.PHISHING,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Initial Access"],
                techniques=["T1566: Phishing", "T1566.001: Spearphishing Attachment",
                             "T1566.002: Spearphishing Link", "T1598: Phishing for Information"],
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=f"Phishing or social-engineering campaign detected with {matched} indicators of email manipulation and deceptive lure content.",
            false_positive_risk="MEDIUM" if matched >= 3 else "HIGH",
        )
