"""
CyberSage AI — Regulatory Compliance Control Mapper

Maps triaged security incidents directly to relevant control requirements from:
- NIST CSF 2.0 (National Institute of Standards and Technology)
- ISO/IEC 27001:2022 (Annex A Controls)
- SOC 2 Type II (Trust Services Criteria CC6, CC7)
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- HIPAA Security Rule (45 CFR Part 164)
- GDPR Article 33 (72-Hour Personal Data Breach Notification Clock)

Enterprise SOC teams use this mapping to immediately understand their
statutory reporting obligations, audit evidence requirements, and framework alignments.
"""

from typing import Optional
from app.schemas.incident import (
    ComplianceRequirement,
    ExtractedIOCs,
    IncidentCategory,
    IncidentSeverity,
)


class ComplianceMapper:
    """
    Evaluates incident category, severity, and extracted IOCs against
    authoritative cybersecurity compliance control catalogs.
    """

    def map_compliance(
        self,
        category: IncidentCategory,
        severity: IncidentSeverity,
        iocs: Optional[ExtractedIOCs] = None,
    ) -> list[ComplianceRequirement]:
        """
        Produce a tailored list of applicable compliance requirements for this incident.
        """
        requirements: list[ComplianceRequirement] = []

        # ======================================================================
        # 1. Base Framework Requirements (Always apply to any security incident)
        # ======================================================================
        requirements.append(
            ComplianceRequirement(
                framework="NIST CSF 2.0",
                control_id="RS.AN-1",
                title="Incident Investigation & Analysis",
                description="Investigate notifications from detection systems to understand incident characteristics and blast radius.",
                relevance_note="Mandatory forensic analysis and evidence gathering for all classified incidents.",
            )
        )
        requirements.append(
            ComplianceRequirement(
                framework="ISO/IEC 27001:2022",
                control_id="A.5.26",
                title="Response to Information Security Incidents",
                description="Respond to information security incidents in accordance with documented incident response procedures.",
                relevance_note="Ensures organizational response strictly adheres to established SOC runbooks.",
            )
        )
        requirements.append(
            ComplianceRequirement(
                framework="SOC 2 Type II",
                control_id="CC7.3",
                title="Incident Response Program",
                description="Execute procedures to detect, analyze, contain, and recover from identified security incidents.",
                relevance_note="Audit evidence required showing documented triage decision and assigned mitigation steps.",
            )
        )

        # ======================================================================
        # 2. Category-Specific Mappings
        # ======================================================================

        if category == IncidentCategory.BRUTE_FORCE:
            requirements.append(
                ComplianceRequirement(
                    framework="NIST CSF 2.0",
                    control_id="PR.AC-1",
                    title="Identities and Credentials Management",
                    description="Identities and credentials for authorized users, services, and hardware are managed, authenticated, and asserted.",
                    relevance_note="Brute force against credentials violates credential assertion and rate-limiting baselines.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="PCI-DSS v4.0",
                    control_id="Req 8.3.4",
                    title="Account Lockout Controls",
                    description="Lock out user IDs after not more than 10 failed access attempts to prevent automated credential guessing.",
                    relevance_note="High-frequency authentication attempts indicate failure or absence of strict lockout controls.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="ISO/IEC 27001:2022",
                    control_id="A.5.15",
                    title="Access Control",
                    description="Rules to control physical and logical access to information and other associated assets must be established.",
                    relevance_note="Enforce Multi-Factor Authentication (MFA) and host-level connection rate limiting.",
                )
            )

        elif category == IncidentCategory.PHISHING:
            requirements.append(
                ComplianceRequirement(
                    framework="NIST CSF 2.0",
                    control_id="PR.AT-1",
                    title="Personnel Awareness & Training",
                    description="All users are informed and trained to recognize social engineering, phishing, and impersonation attempts.",
                    relevance_note="Phishing campaigns require recording recipient metrics for security awareness re-training.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="ISO/IEC 27001:2022",
                    control_id="A.8.7",
                    title="Protection Against Malware & Deceptive Messages",
                    description="Protection against malware and deceptive electronic communications must be implemented and maintained.",
                    relevance_note="Verify SPF, DKIM, and DMARC enforcement at perimeter email security gateways.",
                )
            )

        elif category in (IncidentCategory.MALWARE, IncidentCategory.RANSOMWARE):
            requirements.append(
                ComplianceRequirement(
                    framework="NIST CSF 2.0",
                    control_id="DE.CM-1",
                    title="Continuous Endpoint Monitoring",
                    description="The network environment and endpoints are monitored to detect potential cybersecurity events and malware.",
                    relevance_note="Endpoint execution telemetry and process anomaly detection required for forensic validation.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="PCI-DSS v4.0",
                    control_id="Req 5.2.1",
                    title="Anti-Malware Mechanisms",
                    description="Deploy and actively update anti-malware software on all system components to detect and isolate threats.",
                    relevance_note="Ensures endpoint EDR agents successfully intercepted or quarantined malicious payload.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="HIPAA Security Rule",
                    control_id="45 CFR § 164.308(a)(5)(ii)(B)",
                    title="Protection from Malicious Software",
                    description="Procedures for guarding against, detecting, and reporting malicious software on ePHI-processing systems.",
                    relevance_note="Mandatory audit trail verifying malicious process did not access electronic protected health data.",
                )
            )

        elif category == IncidentCategory.WEB_APPLICATION_ATTACK:
            requirements.append(
                ComplianceRequirement(
                    framework="PCI-DSS v4.0",
                    control_id="Req 6.4.1",
                    title="Web Application Security & WAF",
                    description="Public-facing web applications are protected against known attacks via automated WAF or code analysis.",
                    relevance_note="Detecting SQLi, XSS, or SSRF requires immediate WAF rule tuning and code-level remediation.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="ISO/IEC 27001:2022",
                    control_id="A.8.26",
                    title="Application Security Requirements",
                    description="Information security requirements must be identified, specified, and approved when developing applications.",
                    relevance_note="Review parameterized query enforcement and input validation libraries in codebase.",
                )
            )

        elif category in (IncidentCategory.CLOUD_INFRASTRUCTURE, IncidentCategory.ACTIVE_DIRECTORY, IncidentCategory.UNAUTHORIZED_ACCESS):
            requirements.append(
                ComplianceRequirement(
                    framework="SOC 2 Type II",
                    control_id="CC6.1",
                    title="Logical Access & Principle of Least Privilege",
                    description="Access to sensitive infrastructure and data is restricted according to the principle of least privilege.",
                    relevance_note="Compromised cloud IAM keys or Kerberos tickets indicate breach of logical access boundaries.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="NIST CSF 2.0",
                    control_id="PR.AC-4",
                    title="Access Permissions & Least Privilege Enforcement",
                    description="Access permissions and authorizations are managed incorporating the principles of least privilege.",
                    relevance_note="Immediately revoke overly permissive IAM policies or Domain Admin role assignments.",
                )
            )

        # ======================================================================
        # 3. High-Impact Statutory Notifications (GDPR & Data Exfiltration)
        # ======================================================================
        if (
            category in (IncidentCategory.RANSOMWARE, IncidentCategory.DATA_EXFILTRATION)
            or severity == IncidentSeverity.CRITICAL
        ):
            requirements.append(
                ComplianceRequirement(
                    framework="GDPR",
                    control_id="Article 33",
                    title="72-Hour Personal Data Breach Notification",
                    description=(
                        "In the case of a personal data breach, notify the competent supervisory authority "
                        "without undue delay and, where feasible, not later than 72 hours after having become aware."
                    ),
                    relevance_note="CRITICAL / Ransomware / Exfiltration alerts trigger statutory 72-hour regulatory investigation clock.",
                )
            )
            requirements.append(
                ComplianceRequirement(
                    framework="HIPAA Security Rule",
                    control_id="45 CFR § 164.404",
                    title="Notification to Individuals of a Breach of Unsecured ePHI",
                    description="Notify each individual whose unsecured protected health information has been accessed or acquired.",
                    relevance_note="Evaluate if affected assets or databases store Patient ePHI or customer PII.",
                )
            )

        return requirements
