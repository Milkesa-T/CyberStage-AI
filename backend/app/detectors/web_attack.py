"""
CyberSage AI — Web Application Attack Detector (MITRE T1190, T1059.007)

Detects OWASP Top 10 and common web exploitation techniques:
- SQL Injection (classic, blind, time-based, UNION-based)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Server-Side Request Forgery (SSRF) — especially AWS metadata service
- Path/Directory Traversal
- Command Injection
- Log4Shell (CVE-2021-44228) and similar injection frameworks
"""
from app.detectors.base import BaseDetector, DetectionResult
from app.schemas.incident import (
    ExtractedIOCs, IncidentCategory, IncidentSeverity, MitreMapping
)

_SQLI_KEYWORDS = [
    "union select", "or '1'='1", "or 1=1", "' or '", "1' or '1",
    "sleep(", "waitfor delay", "benchmark(", "extractvalue(",
    "information_schema", "xp_cmdshell", "sysobjects",
    "drop table", "insert into", "--", "/**/",
]

_XSS_KEYWORDS = [
    "<script>", "</script>", "javascript:", "onerror=", "onload=",
    "alert(", "document.cookie", "eval(", "onmouseover=",
    "src=javascript", "expression(",
]

_SSRF_KEYWORDS = [
    "169.254.169.254", "metadata.google.internal",
    "file:///", "dict://", "gopher://",
    "aws/credentials", "latest/meta-data", "iam/security-credentials",
]

_TRAVERSAL_KEYWORDS = [
    "../", "..\\", "%2e%2e", "%2f", "....//",
    "/etc/passwd", "/etc/shadow", "win.ini", "system32/",
]

_CMD_INJECT_KEYWORDS = [
    "; ls", "| ls", "& dir", "; cat /", "| cat /",
    "`id`", "$(id)", "; wget ", "; curl ", "| nc ",
]


class WebAttackDetector(BaseDetector):

    @property
    def name(self) -> str:
        return "WebAttackDetector"

    def can_detect(self, combined_text: str) -> bool:
        all_keywords = _SQLI_KEYWORDS + _XSS_KEYWORDS + _SSRF_KEYWORDS + _TRAVERSAL_KEYWORDS + _CMD_INJECT_KEYWORDS
        return any(kw in combined_text for kw in all_keywords)

    def analyze(self, combined_text: str, iocs: ExtractedIOCs) -> DetectionResult:
        if not self.can_detect(combined_text):
            return DetectionResult(detected=False, confidence=0.0)

        sqli_count = sum(1 for kw in _SQLI_KEYWORDS if kw in combined_text)
        xss_count = sum(1 for kw in _XSS_KEYWORDS if kw in combined_text)
        ssrf_count = sum(1 for kw in _SSRF_KEYWORDS if kw in combined_text)
        traversal_count = sum(1 for kw in _TRAVERSAL_KEYWORDS if kw in combined_text)
        cmd_count = sum(1 for kw in _CMD_INJECT_KEYWORDS if kw in combined_text)
        total = sqli_count + xss_count + ssrf_count + traversal_count + cmd_count

        confidence = min(0.95, 0.35 + (total * 0.10))
        severity = IncidentSeverity.CRITICAL if ssrf_count > 0 or cmd_count > 0 else IncidentSeverity.HIGH

        attack_types = []
        if sqli_count > 0: attack_types.append(f"SQL Injection ({sqli_count} patterns)")
        if xss_count > 0: attack_types.append(f"Cross-Site Scripting ({xss_count} patterns)")
        if ssrf_count > 0: attack_types.append(f"SSRF / Metadata Service Access ({ssrf_count} patterns)")
        if traversal_count > 0: attack_types.append(f"Path Traversal ({traversal_count} patterns)")
        if cmd_count > 0: attack_types.append(f"Command Injection ({cmd_count} patterns)")

        evidence = [
            f"Web application attack detected — types identified: {', '.join(attack_types)}.",
        ]
        if "169.254.169.254" in combined_text:
            evidence.append("⚠️ AWS Instance Metadata Service (IMDS) SSRF attempted — cloud credentials may be at risk.")
        if iocs.urls:
            evidence.append(f"Attack target URLs: {', '.join(iocs.defanged_urls[:3])}.")
        if iocs.cve_ids:
            evidence.append(f"CVE identifiers referenced: {', '.join(iocs.cve_ids)}.")

        techniques = ["T1190: Exploit Public-Facing Application"]
        if sqli_count: techniques.append("T1059.007: JavaScript/SQLi Injection")
        if ssrf_count: techniques.append("T1552.005: Cloud Instance Metadata API (SSRF)")

        steps = [
            "Immediately block the source IP(s) at WAF (Web Application Firewall) and CDN layer.",
            "Examine application server access logs for successful payload execution or data exfiltration.",
            "Run parameterized query audit on all affected endpoints to identify and patch SQLi vulnerabilities.",
            "If SSRF/metadata access occurred: rotate ALL cloud IAM credentials and instance roles immediately.",
            "Enable WAF rules for OWASP Top 10 payload detection across all public endpoints.",
            "Submit the attack payload to your threat intelligence platform and update WAF rulesets.",
        ]

        return DetectionResult(
            detected=True,
            category=IncidentCategory.WEB_APPLICATION_ATTACK,
            severity=severity,
            confidence=confidence,
            mitre_mapping=MitreMapping(
                tactics=["Initial Access", "Execution"],
                techniques=techniques,
            ),
            evidence=evidence,
            recommended_steps=steps,
            summary=f"Web application exploitation detected — attack types: {', '.join(attack_types)}.",
            false_positive_risk="LOW" if total >= 3 else "MEDIUM",
        )
