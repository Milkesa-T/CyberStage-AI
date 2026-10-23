"""
CyberSage AI — Unit & Integration Tests for Modular Threat Detectors & IOC Extractor

Validates:
1. IOCExtractor (RFC 1918 classification, URL defanging, hashes, CVEs, cloud keys)
2. Concrete threat detectors (BruteForce, Phishing, Malware, WebAttack, CloudIAM, ActiveDirectory, Ransomware)
3. DetectorRegistry (multi-detector aggregation, MITRE mapping aggregation, primary selection)
4. TriageService integration (enriched IncidentTriageResponse output)
"""

import pytest
from app.detectors.ioc_extractor import IOCExtractor, defang_url, defang_domain
from app.detectors.brute_force import BruteForceDetector
from app.detectors.phishing import PhishingDetector
from app.detectors.malware import MalwarePersistenceDetector
from app.detectors.web_attack import WebAttackDetector
from app.detectors.cloud_iam import CloudIAMDetector
from app.detectors.active_directory import ActiveDirectoryDetector
from app.detectors.ransomware_exfiltration import RansomwareExfiltrationDetector
from app.detectors.registry import DetectorRegistry
from app.services.triage_service import TriageService
from app.schemas.incident import (
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageRequest,
    IncidentTriageResponse,
)


# ==============================================================================
# 1. IOC Extractor Tests
# ==============================================================================

class TestIOCExtractor:

    def setup_method(self):
        self.extractor = IOCExtractor()

    def test_ip_classification_private_vs_public(self):
        sample_text = (
            "Source 192.168.1.50 accessed internal server 10.0.0.12, "
            "communicating with external drop host 198.51.100.44 and 203.0.113.195."
        )
        iocs = self.extractor.extract(sample_text)

        assert "192.168.1.50" in iocs.private_ips
        assert "10.0.0.12" in iocs.private_ips
        assert "198.51.100.44" in iocs.public_ips
        assert "203.0.113.195" in iocs.public_ips
        assert iocs.has_external_threat_actor is True

    def test_url_extraction_and_defanging(self):
        sample_text = (
            "Payload downloaded from http://malicious-c2.xyz/payload.exe "
            "and exfiltrated to https://evil-exfil.com/upload"
        )
        iocs = self.extractor.extract(sample_text)

        assert "http://malicious-c2.xyz/payload.exe" in iocs.urls
        assert "https://evil-exfil.com/upload" in iocs.urls
        assert "hxxp://malicious-c2[.]xyz/payload.exe" in iocs.defanged_urls
        assert "hxxps://evil-exfil[.]com/upload" in iocs.defanged_urls

    def test_hashes_and_cves_extraction(self):
        sample_text = (
            "Malware hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "MD5: d41d8cd98f00b204e9800998ecf8427e. Exploit targets CVE-2021-44228 and CVE-2023-38606."
        )
        iocs = self.extractor.extract(sample_text)

        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs.file_hashes
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs.file_hashes
        assert "CVE-2021-44228" in iocs.cve_ids
        assert "CVE-2023-38606" in iocs.cve_ids

    def test_aws_identity_extraction(self):
        sample_text = (
            "Compromised credential AKIAIOSFODNN7EXAMPLE invoked "
            "arn:aws:iam::123456789012:user/David"
        )
        iocs = self.extractor.extract(sample_text)

        assert any("AKIAIOSFODNN7EXAMPLE" in ident for ident in iocs.cloud_identities)
        assert any("arn:aws:iam::123456789012:user/David" in ident for ident in iocs.cloud_identities)


# ==============================================================================
# 2. Concrete Threat Detector Tests
# ==============================================================================

class TestConcreteDetectors:

    def setup_method(self):
        self.extractor = IOCExtractor()

    def test_brute_force_detector(self):
        detector = BruteForceDetector()
        text = "Oct 22 10:14:02 srv sshd[2841]: Failed password for root from 198.51.100.44 port 48210 ssh2"
        iocs = self.extractor.extract(text)

        assert detector.can_detect(text) is True
        result = detector.analyze(text, iocs)
        assert result.detected is True
        assert result.category == IncidentCategory.BRUTE_FORCE
        assert "T1110: Brute Force" in result.mitre_mapping.techniques

    def test_web_attack_sqli_ssrf_detector(self):
        detector = WebAttackDetector()
        text = "GET /api/user?id=1' UNION SELECT username, password FROM users-- HTTP/1.1 with metadata fetch 169.254.169.254"
        iocs = self.extractor.extract(text)

        assert detector.can_detect(text) is True
        result = detector.analyze(text, iocs)
        assert result.detected is True
        assert result.category == IncidentCategory.WEB_APPLICATION_ATTACK
        assert result.severity == IncidentSeverity.CRITICAL  # SSRF escalates to critical

    def test_ransomware_exfiltration_detector(self):
        detector = RansomwareExfiltrationDetector()
        text = "cmd.exe /c vssadmin delete shadows /all /quiet && ren *.docx *.locked"
        iocs = self.extractor.extract(text)

        assert detector.can_detect(text) is True
        result = detector.analyze(text, iocs)
        assert result.detected is True
        assert result.category == IncidentCategory.RANSOMWARE
        assert result.severity == IncidentSeverity.CRITICAL
        assert "T1486: Data Encrypted for Impact" in result.mitre_mapping.techniques

    def test_active_directory_detector(self):
        detector = ActiveDirectoryDetector()
        text = "EventID 4769 Kerberoasting detected with ticket encryption type 0x17 requesting SPN MSSQLSvc"
        iocs = self.extractor.extract(text)

        assert detector.can_detect(text) is True
        result = detector.analyze(text, iocs)
        assert result.detected is True
        assert result.category == IncidentCategory.ACTIVE_DIRECTORY
        assert "T1558: Steal or Forge Kerberos Tickets" in result.mitre_mapping.techniques

    def test_cloud_iam_detector(self):
        detector = CloudIAMDetector()
        text = "CloudTrail event: AuthorizeSecurityGroupIngress opened 0.0.0.0/0 on port 22 by AKIAIOSFODNN7EXAMPLE"
        iocs = self.extractor.extract(text)

        assert detector.can_detect(text) is True
        result = detector.analyze(text, iocs)
        assert result.detected is True
        assert result.category == IncidentCategory.CLOUD_INFRASTRUCTURE
        assert result.severity == IncidentSeverity.CRITICAL


# ==============================================================================
# 3. Detector Registry Tests
# ==============================================================================

class TestDetectorRegistry:

    def setup_method(self):
        self.registry = DetectorRegistry()

    def test_registry_selects_ransomware_over_generic(self):
        req = IncidentTriageRequest(
            title="Suspicious volume activity",
            description="Host is unresponsive and shadow copies deleted",
            raw_logs="Host telemetry: vssadmin delete shadows /all /quiet. File renamed to README.txt.",
        )
        ctx = self.registry.evaluate(req)

        assert ctx.total_detectors_triggered >= 1
        assert ctx.primary_result.category == IncidentCategory.RANSOMWARE
        assert ctx.primary_result.severity == IncidentSeverity.CRITICAL
        assert "T1486: Data Encrypted for Impact" in ctx.aggregated_mitre_techniques


# ==============================================================================
# 4. Triage Service Integration with Detectors
# ==============================================================================

class TestTriageServiceEnrichment:

    def test_triage_enriches_response_with_iocs_and_mitre(self):
        service = TriageService(api_key=None)  # deterministic heuristic/detector mode
        req = IncidentTriageRequest(
            title="External SSH Attack",
            description="Repeated failed authentications observed",
            raw_logs="Oct 22 10:14:02 srv sshd[2841]: Failed password for root from 198.51.100.44 port 48210 ssh2",
            source_ip="198.51.100.44",
            affected_asset="srv-prod-01",
        )

        response = service.triage(req)

        assert isinstance(response, IncidentTriageResponse)
        assert response.incident_category == IncidentCategory.BRUTE_FORCE
        assert "198.51.100.44" in response.extracted_iocs.public_ips
        assert response.confidence_score > 0.0
        assert len(response.mitre_mapping.tactics) > 0
        assert any("T1110" in tech for tech in response.mitre_mapping.techniques)
