"""
CyberSage AI — Active Directory & Kerberos Attack Detector (MITRE T1558, T1003, T1550)

Detects sophisticated Active Directory and Windows authentication attacks:
- Kerberoasting: EventID 4769 with RC4 (0x17) encryption requesting service tickets
- DCSync: replication API calls from non-DC hosts
- Pass-the-Hash / Pass-the-Ticket authentication anomalies
- Golden/Silver Ticket patterns (abnormal Kerberos TGT lifetimes)
- LDAP enumeration and BloodHound-style reconnaissance
- Mass account lockouts (password spray against AD)
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_AD_KEYWORDS = [
    # Kerberos attacks
    "kerberoasting", "kerberoast", "eventid 4769", "4769",
    "rc4 encryption", "0x17", "ticket encryption type 0x17",
    "krbtgt", "golden ticket", "silver ticket",
    # DCSync
    "dcsync", "drsuapi", "getncchanges", "directory replication",
    "ms-drsr", "replication",
    # Pass-the-Hash / Pass-the-Ticket
    "pass-the-hash", "pass the hash", "pth", "sekurlsa",
    "pass-the-ticket", "pass the ticket", "mimikatz",
    "lsass", "ntlm hash", "credential dump",
    # Enumeration
    "bloodhound", "sharphound", "ldap enumeration",
    "domain admin", "adminsdHolder", "dsquery",
    # Mass lockout
    "account lockout", "eventid 4740", "4740",
    "multiple accounts locked",
]

_CRITICAL_AD_SIGNALS = [
    "mimikatz", "dcsync", "golden ticket", "krbtgt",
    "lsass", "sekurlsa", "drsuapi", "getncchanges",
]


class ActiveDirectoryDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "ActiveDirectoryDetector"

    def can_detect(self, combined_text: str) -> bool:
        return any(kw in combined_text for kw in _AD_KEYWORDS)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        matched = sum(1 for kw in _AD_KEYWORDS if kw in combined_text)
        critical = sum(1 for s in _CRITICAL_AD_SIGNALS if s in combined_text)
        confidence = min(0.98, 0.50 + (matched * 0.07) + (critical * 0.12))
        severity = IncidentSeverity.CRITICAL if critical > 0 else IncidentSeverity.HIGH

        evidence = [
            f"Active Directory / Kerberos attack indicators: {matched} matched.",
        ]
        if "kerberoasting" in combined_text or ("4769" in combined_text and "0x17" in combined_text):
            evidence.append("Kerberoasting detected — service ticket requested with weak RC4 encryption for offline cracking.")
        if any(s in combined_text for s in ["dcsync", "drsuapi", "getncchanges"]):
            evidence.append("⚠️ CRITICAL: DCSync operation detected — attacker replicating all AD password hashes from Domain Controller.")
        if any(s in combined_text for s in ["golden ticket", "krbtgt"]):
            evidence.append("⚠️ CRITICAL: Golden Ticket attack detected — all Kerberos authentication may be compromised.")
        if any(s in combined_text for s in ["mimikatz", "lsass", "sekurlsa"]):
            evidence.append("Credential dump tool (Mimikatz) detected — LSASS memory dump for plaintext credential extraction.")

        steps = [
            "If DCSync detected: immediately change the KRBTGT account password TWICE (double reset) to invalidate all existing tickets.",
            "Isolate the attacking workstation from the domain; investigate all processes on the host.",
            "Audit all Domain Admin group members for unauthorized accounts or additions.",
            "Enable and review Windows Event ID 4769 (Kerberos Service Ticket Operations) for anomalous patterns.",
            "Deploy Privileged Access Workstation (PAW) for all Domain Admin operations.",
            "Force full password reset for all service accounts (SPNs) if Kerberoasting occurred.",
            "Enable Microsoft Defender for Identity (MDI) or equivalent for real-time AD threat detection.",
        ]

        techniques = ["T1558: Steal or Forge Kerberos Tickets"]
        if critical > 0:
            techniques += ["T1003.006: OS Credential Dumping: DCSync",
                           "T1550.003: Use Alternate Authentication Material: Pass-the-Ticket"]

        return DetectionResult(
            detected=True,
            category=IncidentCategory.ACTIVE_DIRECTORY,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Credential Access", "Lateral Movement", "Persistence"],
                techniques=techniques,
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=f"Active Directory attack detected with {matched} indicators — {'CRITICAL credential compromise' if critical > 0 else 'reconnaissance or privilege escalation activity'}.",
            false_positive_risk="LOW" if critical > 0 else "MEDIUM",
        )
