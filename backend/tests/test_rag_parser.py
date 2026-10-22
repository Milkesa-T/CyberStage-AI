import pytest
import os
import tempfile
from app.rag.parser import parse_all_playbooks, parse_playbook_file, PlaybookChunk


SAMPLE_PLAYBOOK = """# Test Incident Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-TEST-001
- **Category**: TEST_CATEGORY
- **Description**: A sample playbook for automated unit testing of the parser.

## 2. Key Indicators of Compromise (IOCs)
- Unusual outbound traffic patterns detected in network flow logs.
- Suspicious process creation events logged by the EDR solution.
- Multiple failed authentication events from a single source IP.

## 3. Triage and Initial Verification Steps
1. Verify alert authenticity against multiple telemetry sources.
2. Check network topology maps for affected hosts.
3. Review authentication logs for correlated events.

## 4. Containment Actions
1. Isolate the affected endpoint from the corporate network.
2. Block malicious IP addresses at the perimeter firewall.
3. Revoke compromised credentials and refresh tokens.
"""


@pytest.fixture
def sample_playbook_file(tmp_path):
    """Write a sample playbook to a temp file and return its path."""
    playbook_path = tmp_path / "PB-TEST-001-UNIT.md"
    playbook_path.write_text(SAMPLE_PLAYBOOK, encoding="utf-8")
    return str(playbook_path)


@pytest.fixture
def sample_playbooks_dir(tmp_path):
    """Write two sample playbooks to a temp directory and return its path."""
    (tmp_path / "PB-ALPHA.md").write_text(SAMPLE_PLAYBOOK.replace("PB-TEST-001", "PB-ALPHA"), encoding="utf-8")
    (tmp_path / "PB-BETA.md").write_text(SAMPLE_PLAYBOOK.replace("PB-TEST-001", "PB-BETA"), encoding="utf-8")
    return str(tmp_path)


def test_parse_playbook_file_returns_chunks(sample_playbook_file):
    """Parser should produce one chunk per H2 section with sufficient content."""
    chunks = parse_playbook_file(sample_playbook_file)
    assert len(chunks) == 4, f"Expected 4 sections, got {len(chunks)}"


def test_chunk_has_required_fields(sample_playbook_file):
    """Each chunk must have all required fields populated."""
    chunks = parse_playbook_file(sample_playbook_file)
    for chunk in chunks:
        assert isinstance(chunk, PlaybookChunk)
        assert chunk.chunk_id, "chunk_id must not be empty"
        assert chunk.playbook_id == "PB-TEST-001-UNIT"
        assert "Test Incident Response Playbook" in chunk.playbook_title
        assert chunk.section, "section must not be empty"
        assert len(chunk.text) >= 50, "chunk text too short"


def test_chunk_id_is_unique(sample_playbook_file):
    """All chunk IDs within a playbook must be unique."""
    chunks = parse_playbook_file(sample_playbook_file)
    ids = [c.chunk_id for c in chunks]
    assert len(ids) == len(set(ids)), "Duplicate chunk IDs detected!"


def test_parse_all_playbooks_aggregates_multiple_files(sample_playbooks_dir):
    """parse_all_playbooks should combine chunks from multiple files."""
    chunks = parse_all_playbooks(sample_playbooks_dir)
    assert len(chunks) > 4, "Should have chunks from both test playbooks"


def test_parse_all_playbooks_handles_missing_directory():
    """Parser should return an empty list (not raise) for missing directory."""
    chunks = parse_all_playbooks("/nonexistent/path/playbooks")
    assert chunks == [], "Should return empty list for missing directory"
