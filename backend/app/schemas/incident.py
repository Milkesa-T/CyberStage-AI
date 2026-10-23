"""
CyberSage AI — Incident Triage Domain Schemas

Defines Pydantic v2 models for request validation, response contracts,
forensic IOC extraction, MITRE ATT&CK mapping, regulatory compliance,
enterprise SOC SLA calculation, and executable remediation scripts.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ==============================================================================
# Enumerations
# ==============================================================================

class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(str, Enum):
    """
    Enterprise threat taxonomy covering the full spectrum of SOC-observed attack patterns.
    Aligned with MITRE ATT&CK tactics and NIST SP 800-61r2 incident classifications.
    """
    BRUTE_FORCE = "BRUTE_FORCE"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    WEB_APPLICATION_ATTACK = "WEB_APPLICATION_ATTACK"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
    CLOUD_INFRASTRUCTURE = "CLOUD_INFRASTRUCTURE"
    INSIDER_THREAT = "INSIDER_THREAT"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    OTHER = "OTHER"


class FalsePositiveRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ==============================================================================
# Forensic Indicator-of-Compromise (IOC) Schema
# ==============================================================================

class ExtractedIOCs(BaseModel):
    """
    Structured forensic artifact container holding all Indicators of Compromise
    automatically extracted from raw incident telemetry.

    IP Addresses are split into private (RFC 1918) and public (WAN-routable) to
    immediately distinguish internal lateral movement from external ingress.
    Defanged URLs use the analyst-safe format (hxxp://, evil[.]com) preventing
    accidental click-through.
    """
    ipv4_addresses: list[str] = Field(
        default_factory=list,
        description="All IPv4 addresses extracted from telemetry"
    )
    ipv6_addresses: list[str] = Field(
        default_factory=list,
        description="All IPv6 addresses extracted from telemetry"
    )
    private_ips: list[str] = Field(
        default_factory=list,
        description="RFC 1918 private IPs (10.x, 192.168.x, 172.16-31.x) — indicates internal movement"
    )
    public_ips: list[str] = Field(
        default_factory=list,
        description="Publicly routable WAN IPs — indicates external threat actor origin"
    )
    domains: list[str] = Field(
        default_factory=list,
        description="Fully qualified domain names (FQDNs) extracted from telemetry"
    )
    urls: list[str] = Field(
        default_factory=list,
        description="Full URLs (HTTP/HTTPS) extracted from telemetry"
    )
    defanged_urls: list[str] = Field(
        default_factory=list,
        description="Safety-defanged URL representations for analyst display (hxxp://, [.])"
    )
    file_hashes: list[str] = Field(
        default_factory=list,
        description="MD5, SHA1, and SHA256 file hashes extracted from telemetry"
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="CVE identifiers (CVE-YYYY-NNNNN) referenced in telemetry"
    )
    cloud_identities: list[str] = Field(
        default_factory=list,
        description="AWS Access Keys, ARN identifiers, and other cloud identity artifacts"
    )

    @property
    def has_external_threat_actor(self) -> bool:
        """Returns True if any publicly routable IP was extracted."""
        return len(self.public_ips) > 0

    @property
    def ioc_count(self) -> int:
        """Total number of unique IOCs extracted."""
        return (len(self.ipv4_addresses) + len(self.ipv6_addresses) +
                len(self.domains) + len(self.file_hashes) +
                len(self.cve_ids) + len(self.cloud_identities))


# ==============================================================================
# MITRE ATT&CK Mapping Schema
# ==============================================================================

class MitreMapping(BaseModel):
    """
    Structured mapping to MITRE ATT&CK framework tactics and techniques,
    derived from the threat detector analysis.
    """
    tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK Tactics (e.g., 'Credential Access', 'Lateral Movement')",
        examples=[["Credential Access", "Persistence"]]
    )
    techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK Technique IDs with names (e.g., 'T1110: Brute Force')",
        examples=[["T1110: Brute Force", "T1078: Valid Accounts"]]
    )


# ==============================================================================
# Regulatory Compliance Schema (Phase 2)
# ==============================================================================

class ComplianceRequirement(BaseModel):
    """
    Specific control requirement from a major cybersecurity compliance framework
    triggered by this incident's category and severity.
    """
    framework: str = Field(
        ...,
        description="Regulatory framework name (e.g. 'NIST CSF 2.0', 'ISO 27001:2022', 'SOC 2 Type II', 'PCI-DSS v4.0', 'GDPR', 'HIPAA')",
        examples=["NIST CSF 2.0", "ISO 27001:2022", "GDPR"]
    )
    control_id: str = Field(
        ...,
        description="Identifier of the specific control or article (e.g. 'DE.CM-1', 'A.8.16', 'Article 33')",
        examples=["DE.CM-1", "A.8.16", "CC7.2"]
    )
    title: str = Field(
        ...,
        description="Title or requirement summary of the control",
        examples=["Continuous Monitoring", "Network Security Management"]
    )
    description: str = Field(
        ...,
        description="Obligation or action required by the control in response to this incident"
    )
    relevance_note: str = Field(
        ...,
        description="Specific reason this control is cited for the detected incident category"
    )


# ==============================================================================
# SOC SLA Deadlines Schema (Phase 2)
# ==============================================================================

class SLADeadline(BaseModel):
    """
    Enterprise SOC Service Level Agreement (SLA) deadlines and escalation paths.
    Enforces Mean Time to Acknowledge (MTTA) and Mean Time to Remediate (MTTR).
    """
    mtta_minutes: int = Field(
        ...,
        description="Mean Time to Acknowledge SLA in minutes",
        examples=[15]
    )
    mttr_minutes: int = Field(
        ...,
        description="Mean Time to Remediate SLA in minutes",
        examples=[60]
    )
    acknowledge_deadline_utc: datetime = Field(
        ...,
        description="UTC deadline by which an analyst must triage and assign the incident"
    )
    remediate_deadline_utc: datetime = Field(
        ...,
        description="UTC deadline by which containment and mitigation must be completed"
    )
    escalation_tier: str = Field(
        ...,
        description="Designated escalation authority (e.g. 'Tier-3 Senior SOC & CISO On-Call')",
        examples=["Tier-3 Senior SOC & CISO On-Call"]
    )
    regulatory_breach_window: Optional[str] = Field(
        None,
        description="Active regulatory countdown window if applicable (e.g. GDPR 72-Hour notification clock)",
        examples=["GDPR Art. 33 — 72-hour notification deadline to supervisory authority if PII compromised"]
    )


# ==============================================================================
# Executable Remediation Script Schema (Phase 2)
# ==============================================================================

class RemediationScript(BaseModel):
    """
    Copy-paste ready, parameterized terminal command scripts for defensive containment.
    Populated directly with extracted incident IOCs (IPs, hashes, domains, cloud keys).
    """
    platform: str = Field(
        ...,
        description="Operating system or execution environment (e.g. 'Linux (iptables)', 'Windows (PowerShell)', 'AWS CLI', 'DNS Sinkhole')",
        examples=["Linux (iptables / ufw)", "Windows (PowerShell)", "AWS CLI"]
    )
    action: str = Field(
        ...,
        description="Defensive action performed by this script",
        examples=["Block hostile source IP at perimeter firewall", "Deactivate exposed AWS Access Key"]
    )
    commands: list[str] = Field(
        ...,
        description="Sequence of executable shell commands ready for analyst copy-paste execution"
    )
    rollback_commands: list[str] = Field(
        default_factory=list,
        description="Commands to revert this action in case of false positive"
    )
    safe_mode_note: Optional[str] = Field(
        None,
        description="Operational safety warning or permission prerequisite (e.g. requires sudo/Domain Admin)"
    )


# ==============================================================================
# Core Request & Response Schemas
# ==============================================================================

class SourceReference(BaseModel):
    """
    Playbook source reference cited in the RAG triage assessment.
    """
    playbook_id: str = Field(..., description="Unique playbook identifier")
    playbook_title: str = Field(..., description="Human-readable title of the playbook")
    section: str = Field(..., description="Relevant section heading in the playbook")
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="Cosine similarity score (0.0 to 1.0)")
    excerpt: str = Field(..., description="Key excerpt from the retrieved playbook section")


class IncidentTriageRequest(BaseModel):
    """
    Incident submission payload from a security analyst or ingestion pipeline.
    """
    title: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description="Brief summary or alert subject",
        examples=["Repeated failed SSH attempts from external IP"]
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=3000,
        description="Analyst notes, event context, or observable symptoms",
        examples=["Host auth.log shows 150 failed root login attempts within 2 minutes."]
    )
    raw_logs: str = Field(
        ...,
        min_length=10,
        max_length=20000,
        description="Raw log lines, syslog entries, or alert JSON excerpt",
        examples=["Oct 22 10:14:02 srv-prod-01 sshd[2841]: Failed password for root from 198.51.100.44 port 48210 ssh2"]
    )
    source_ip: Optional[str] = Field(
        None,
        max_length=45,
        description="Optional source IP address (IPv4 or IPv6)",
        examples=["198.51.100.44"]
    )
    affected_asset: Optional[str] = Field(
        None,
        max_length=100,
        description="Optional affected hostname, instance ID, or service",
        examples=["srv-prod-01"]
    )


class IncidentTriageResponse(BaseModel):
    """
    Structured triage assessment produced by CyberSage AI.

    Enterprise Fields:
    - Phase 1: extracted_iocs, mitre_mapping, confidence_score, false_positive_risk
    - Phase 2: compliance_mappings, sla_deadline, remediation_scripts
    """
    incident_id: str = Field(..., description="Unique incident triage identifier (UUID)")
    timestamp: datetime = Field(..., description="UTC timestamp of the assessment")
    suggested_severity: IncidentSeverity = Field(..., description="Suggested defensive severity level")
    incident_category: IncidentCategory = Field(..., description="Classified incident category")
    summary: str = Field(..., description="Executive summary of the triage findings")
    supporting_evidence: list[str] = Field(..., description="Observable evidence points extracted from logs and context")
    uncertainty_limitations: str = Field(..., description="Known uncertainties, blind spots, or missing telemetry")
    recommended_steps: list[str] = Field(..., description="Prescriptive defensive investigation and containment steps")
    source_references: list[SourceReference] = Field(
        default_factory=list,
        description="Cited defensive playbooks retrieved from the knowledge base"
    )

    # Phase 1 enrichment fields
    extracted_iocs: ExtractedIOCs = Field(
        default_factory=ExtractedIOCs,
        description="Forensic Indicators of Compromise automatically extracted from telemetry"
    )
    mitre_mapping: MitreMapping = Field(
        default_factory=MitreMapping,
        description="MITRE ATT&CK tactic and technique attribution"
    )
    confidence_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Composite detection confidence score from the modular detector analysis (0.0 to 1.0)"
    )
    false_positive_risk: FalsePositiveRisk = Field(
        default=FalsePositiveRisk.MEDIUM,
        description="Estimated likelihood this alert is a benign false positive"
    )

    # Phase 2 enterprise enrichment fields
    compliance_mappings: list[ComplianceRequirement] = Field(
        default_factory=list,
        description="Regulatory and security compliance framework control mappings"
    )
    sla_deadline: Optional[SLADeadline] = Field(
        None,
        description="Calculated enterprise SOC response SLA deadlines and escalation targets"
    )
    remediation_scripts: list[RemediationScript] = Field(
        default_factory=list,
        description="Generated copy-paste executable remediation scripts for rapid containment"
    )
