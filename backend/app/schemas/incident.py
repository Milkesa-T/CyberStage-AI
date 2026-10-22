from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, IPvAnyAddress


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    OTHER = "OTHER"


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
