"""
CyberSage AI — Unit & Integration Tests for Regulatory Compliance, SOC SLAs & Remediation Scripts

Validates Phase 2 features:
1. ComplianceMapper: Framework control mapping across NIST CSF 2.0, ISO 27001, SOC 2, PCI-DSS, HIPAA, GDPR.
2. SLACalculator: Enterprise MTTA/MTTR response deadlines, escalation tiers, and GDPR 72h countdown.
3. RemediationGenerator: Parameterized shell scripts for Linux (iptables/ufw), Windows (PowerShell), AWS CLI, and EDR.
4. TriageService Integration: Full response serialization with Phase 1 & Phase 2 enrichments.
"""

from datetime import datetime, timezone
import pytest
from app.compliance.mapper import ComplianceMapper
from app.compliance.sla import SLACalculator
from app.detectors.ioc_extractor import IOCExtractor
from app.remediation.generator import RemediationGenerator
from app.services.triage_service import TriageService
from app.schemas.incident import (
    ComplianceRequirement,
    ExtractedIOCs,
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageRequest,
    IncidentTriageResponse,
    RemediationScript,
    SLADeadline,
)


# ==============================================================================
# 1. Compliance Mapper Tests
# ==============================================================================

class TestComplianceMapper:

    def setup_method(self):
        self.mapper = ComplianceMapper()

    def test_base_controls_included_for_all_incidents(self):
        reqs = self.mapper.map_compliance(IncidentCategory.OTHER, IncidentSeverity.LOW)
        frameworks = {r.framework for r in reqs}
        control_ids = {r.control_id for r in reqs}

        assert "NIST CSF 2.0" in frameworks
        assert "ISO/IEC 27001:2022" in frameworks
        assert "SOC 2 Type II" in frameworks
        assert "RS.AN-1" in control_ids
        assert "A.5.26" in control_ids
        assert "CC7.3" in control_ids

    def test_brute_force_triggers_pci_and_nist_credentials(self):
        reqs = self.mapper.map_compliance(IncidentCategory.BRUTE_FORCE, IncidentSeverity.HIGH)
        control_ids = {r.control_id for r in reqs}

        assert "Req 8.3.4" in control_ids  # PCI-DSS lockout
        assert "PR.AC-1" in control_ids    # NIST identities/credentials
        assert "A.5.15" in control_ids     # ISO access control

    def test_ransomware_critical_triggers_gdpr_and_hipaa(self):
        reqs = self.mapper.map_compliance(IncidentCategory.RANSOMWARE, IncidentSeverity.CRITICAL)
        frameworks = {r.framework for r in reqs}
        control_ids = {r.control_id for r in reqs}

        assert "GDPR" in frameworks
        assert "Article 33" in control_ids  # 72-hour notification clock
        assert "HIPAA Security Rule" in frameworks


# ==============================================================================
# 2. SOC SLA Calculator Tests
# ==============================================================================

class TestSLACalculator:

    def setup_method(self):
        self.calculator = SLACalculator()

    def test_critical_sla_timing_and_escalation(self):
        base_time = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        sla = self.calculator.calculate(
            severity=IncidentSeverity.CRITICAL,
            category=IncidentCategory.RANSOMWARE,
            incident_time=base_time,
        )

        assert sla.mtta_minutes == 15
        assert sla.mttr_minutes == 60
        assert "CISO" in sla.escalation_tier
        assert sla.regulatory_breach_window is not None
        assert "GDPR Article 33" in sla.regulatory_breach_window

    def test_high_sla_timing(self):
        base_time = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        sla = self.calculator.calculate(
            severity=IncidentSeverity.HIGH,
            category=IncidentCategory.PHISHING,
            incident_time=base_time,
        )

        assert sla.mtta_minutes == 30
        assert sla.mttr_minutes == 240
        assert sla.acknowledge_deadline_utc > base_time
        assert sla.remediate_deadline_utc > sla.acknowledge_deadline_utc

    def test_medium_and_low_sla_timing(self):
        med_sla = self.calculator.calculate(IncidentSeverity.MEDIUM, IncidentCategory.OTHER)
        assert med_sla.mtta_minutes == 120
        assert med_sla.mttr_minutes == 1440

        low_sla = self.calculator.calculate(IncidentSeverity.LOW, IncidentCategory.OTHER)
        assert low_sla.mtta_minutes == 480
        assert low_sla.mttr_minutes == 4320


# ==============================================================================
# 3. Remediation Script Generator Tests
# ==============================================================================

class TestRemediationGenerator:

    def setup_method(self):
        self.generator = RemediationGenerator()
        self.extractor = IOCExtractor()

    def test_generates_firewall_rules_for_extracted_ip(self):
        text = "Failed logins from 198.51.100.44 on sshd"
        iocs = self.extractor.extract(text)

        scripts = self.generator.generate(
            category=IncidentCategory.BRUTE_FORCE,
            severity=IncidentSeverity.HIGH,
            iocs=iocs,
            affected_asset="srv-auth-01",
        )

        platforms = [s.platform for s in scripts]
        assert any("Linux" in p for p in platforms)
        assert any("Windows" in p for p in platforms)

        linux_script = next(s for s in scripts if "Linux" in s.platform)
        assert any("198.51.100.44" in cmd for cmd in linux_script.commands)
        assert any("iptables -I INPUT" in cmd for cmd in linux_script.commands)
        assert any("iptables -D INPUT" in cmd for cmd in linux_script.rollback_commands)

    def test_generates_aws_remediation_when_cloud_key_present(self):
        text = "Compromised key AKIAIOSFODNN7EXAMPLE accessed bucket"
        iocs = self.extractor.extract(text)

        scripts = self.generator.generate(
            category=IncidentCategory.CLOUD_INFRASTRUCTURE,
            severity=IncidentSeverity.CRITICAL,
            iocs=iocs,
        )

        aws_script = next((s for s in scripts if "AWS CLI" in s.platform), None)
        assert aws_script is not None
        assert any("AKIAIOSFODNN7EXAMPLE" in cmd for cmd in aws_script.commands)
        assert any("update-access-key --access-key-id" in cmd for cmd in aws_script.commands)
        assert any("AWSDenyAll" in cmd for cmd in aws_script.commands)

    def test_generates_endpoint_isolation_for_ransomware(self):
        text = "vssadmin delete shadows on db-server-01"
        iocs = self.extractor.extract(text)

        scripts = self.generator.generate(
            category=IncidentCategory.RANSOMWARE,
            severity=IncidentSeverity.CRITICAL,
            iocs=iocs,
            affected_asset="db-server-01",
        )

        isolation_script = next((s for s in scripts if "Isolation" in s.platform), None)
        assert isolation_script is not None
        assert "db-server-01" in isolation_script.action
        assert any("iptables -P INPUT DROP" in cmd for cmd in isolation_script.commands)


# ==============================================================================
# 4. Triage Service Full Integration Test
# ==============================================================================

class TestTriageServicePhase2Integration:

    def test_triage_populates_compliance_sla_and_remediation(self):
        service = TriageService(api_key=None)  # deterministic mode
        req = IncidentTriageRequest(
            title="Active Ransomware Outbreak",
            description="Mass encryption detected on finance share",
            raw_logs="cmd.exe /c vssadmin delete shadows /all /quiet && ren *.xlsx *.locked from 198.51.100.99",
            source_ip="198.51.100.99",
            affected_asset="fs-finance-01",
        )

        response = service.triage(req)

        assert isinstance(response, IncidentTriageResponse)
        assert response.suggested_severity == IncidentSeverity.CRITICAL
        assert response.incident_category == IncidentCategory.RANSOMWARE

        # Verify Compliance Mapping
        assert len(response.compliance_mappings) > 0
        frameworks = {c.framework for c in response.compliance_mappings}
        assert "NIST CSF 2.0" in frameworks
        assert "GDPR" in frameworks  # Critical / Ransomware triggers GDPR Art 33

        # Verify SLA Deadlines
        assert response.sla_deadline is not None
        assert response.sla_deadline.mtta_minutes == 15
        assert response.sla_deadline.mttr_minutes == 60
        assert "CISO" in response.sla_deadline.escalation_tier
        assert response.sla_deadline.regulatory_breach_window is not None

        # Verify Remediation Scripts
        assert len(response.remediation_scripts) > 0
        platforms = [s.platform for s in response.remediation_scripts]
        assert any("Linux" in p for p in platforms)
        assert any("Isolation" in p for p in platforms)
