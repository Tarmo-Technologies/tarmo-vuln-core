"""Unit tests for the Nikto XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.nikto import NiktoIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestNiktoIngestor:
    def setup_method(self) -> None:
        self.ingestor = NiktoIngestor()

    # -- can_handle() ---------------------------------------------------------

    def test_can_handle_nikto(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nikto_real.xml") is True

    def test_cannot_handle_wrong_format(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    # -- ingest() error handling ----------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    # -- Finding correctness --------------------------------------------------

    def test_ingest_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        assert len(findings) == 13

    def test_ingest_specific_field(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        titles = [f.title for f in findings]
        assert "The anti-clickjacking X-Frame-Options header is not present" in titles

    def test_ingest_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        assert all(f.source_tool == "nikto" for f in findings)

    def test_ingest_affected_host_includes_port(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        assert all("127.0.0.1:8070" in f.affected_hosts for f in findings)

    def test_ingest_xss_finding_severity_high(self) -> None:
        """XSS findings should be classified as HIGH severity."""
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        by_id = {f.id: f for f in findings}
        # nikto-000834 is the myphpnuke XSS finding
        assert by_id["nikto-000834"].severity == Severity.HIGH

    def test_ingest_x_frame_options_severity_low(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        by_id = {f.id: f for f in findings}
        assert by_id["nikto-999976"].severity == Severity.LOW

    def test_ingest_allowed_http_methods_present(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nikto_real.xml")
        titles = [f.title for f in findings]
        assert "Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS" in titles

    # -- Truncated XML support (issue #47) ------------------------------------

    def test_can_handle_truncated_xml(self) -> None:
        """can_handle() should return True for truncated Nikto XML with valid items."""
        assert self.ingestor.can_handle(FIXTURES / "nikto_truncated.xml") is True

    def test_ingest_truncated_xml_recovers_findings(self) -> None:
        """ingest() should recover findings from truncated Nikto XML."""
        findings = self.ingestor.ingest(FIXTURES / "nikto_truncated.xml")
        assert len(findings) >= 1
        titles = [f.title for f in findings]
        assert "The anti-clickjacking X-Frame-Options header is not present" in titles
        assert all("127.0.0.1:8070" in f.affected_hosts for f in findings)
