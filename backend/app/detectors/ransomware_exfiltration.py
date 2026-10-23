"""
CyberSage AI — Ransomware & Data Exfiltration Detector (MITRE T1486, T1048, T1041)

Detects ransomware deployment and large-scale data exfiltration:
- Shadow Volume Copy deletion (vssadmin delete shadows — #1 ransomware indicator)
- Mass file encryption indicators (bulk file rename to .locked, .encrypt, .ransom etc.)
- Ransom note file creation (README.txt, HOW_TO_DECRYPT.txt)
- DNS tunneling exfiltration
- Large outbound data transfer to external storage (S3, Mega, Dropbox, Pastebin)
- Wiper patterns (dd, shred, DISKPART clean)
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_RANSOMWARE_KEYWORDS = [
    # Shadow copy deletion — single highest-confidence ransomware pre-cursor
    "vssadmin delete shadows", "vssadmin.exe delete",
    "wmic shadowcopy delete", "delete shadows",
    # File encryption indicators
    ".locked", ".encrypted", ".ransom", ".crypt", ".crypted",
    ".wncry", ".zepto", ".locky", ".cerber",
    "readme.txt", "how_to_decrypt", "your_files_are_encrypted",
    "decrypt_instructions", "recover_files",
    # Wiper patterns
    "shred -", "dd if=/dev/zero", "diskpart", "format c:",
    # Exfiltration
    "dns tunnel", "dnstunnel", "dnscat",
    "mega.nz", "anonfiles", "transfer.sh",
    "large transfer", "exfiltrat", "data theft", "data breach",
    "curl -T", "wget --post-file",
]

_CRITICAL_RANSOMWARE = [
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "how_to_decrypt", "your_files_are_encrypted",
    "shred -", "dd if=/dev/zero",
]


class RansomwareExfiltrationDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "RansomwareExfiltrationDetector"

    def can_detect(self, combined_text: str) -> bool:
        return any(kw in combined_text for kw in _RANSOMWARE_KEYWORDS)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        matched = sum(1 for kw in _RANSOMWARE_KEYWORDS if kw in combined_text)
        critical = sum(1 for s in _CRITICAL_RANSOMWARE if s in combined_text)
        confidence = min(0.99, 0.55 + (matched * 0.08) + (critical * 0.15))
        severity = IncidentSeverity.CRITICAL  # Ransomware is always critical

        evidence = [
            f"Ransomware / destructive attack indicators: {matched} patterns matched.",
        ]
        if "vssadmin delete shadows" in combined_text or "wmic shadowcopy delete" in combined_text:
            evidence.append("⚠️ CRITICAL: Shadow Volume Copy deletion detected — #1 ransomware pre-encryption indicator. Immediate action required.")
        if any(ext in combined_text for ext in [".wncry", ".locked", ".ransom", ".encrypted", ".crypt"]):
            evidence.append("File extension mass-rename to encrypted extension detected — encryption may already be in progress.")
        if any(n in combined_text for n in ["how_to_decrypt", "readme.txt", "your_files_are_encrypted"]):
            evidence.append("Ransom note file creation detected — ransomware payload has already executed on this host.")
        if iocs.public_ips:
            evidence.append(f"External exfiltration destinations: {', '.join(iocs.public_ips[:3])}.")
        if iocs.domains:
            evidence.append(f"External domains contacted: {', '.join(iocs.defanged_urls[:2] or iocs.domains[:2])}.")

        steps = [
            "⚡ EMERGENCY: IMMEDIATELY disconnect affected hosts from all network segments (pull ethernet cable if needed).",
            "Do NOT restart affected systems — running ransomware processes may encrypt remaining data.",
            "Activate your organization's Ransomware Incident Response Plan (IRP) and notify senior leadership.",
            "Identify and isolate the Patient Zero host — trace spread via network connection logs.",
            "Check backup integrity and air-gapped copies BEFORE attempting any recovery.",
            "Report to law enforcement (FBI IC3 in USA, NCSC in UK) and legal/compliance teams.",
            "Preserve forensic artifacts from isolated hosts for investigation before wiping.",
        ]

        techniques = ["T1486: Data Encrypted for Impact", "T1490: Inhibit System Recovery"]
        if any(k in combined_text for k in ["exfiltrat", "dns tunnel", "large transfer", "mega.nz"]):
            techniques.append("T1048: Exfiltration Over Alternative Protocol")
            techniques.append("T1041: Exfiltration Over C2 Channel")

        return DetectionResult(
            detected=True,
            category=IncidentCategory.RANSOMWARE,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Impact", "Exfiltration"],
                techniques=techniques,
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=f"Ransomware or destructive attack detected with {matched} critical indicators — {critical} pre-encryption signals confirmed.",
            false_positive_risk="LOW",  # Shadow copy deletion is rarely benign
        )
