"""Unit tests for the Acunetix XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.acunetix import AcunetixIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestAcunetixIngestor:
    def setup_method(self) -> None:
        self.ingestor = AcunetixIngestor()

    # -- can_handle() ---------------------------------------------------------

    def test_can_handle_acunetix(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "acunetix_real.xml") is True

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
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        assert len(findings) == 4

    def test_ingest_specific_field(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        titles = [f.title for f in findings]
        assert "Slow HTTP Denial of Service Attack" in titles

    def test_ingest_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        by_title = {f.title: f for f in findings}
        assert by_title["Slow HTTP Denial of Service Attack"].severity == Severity.MEDIUM

    def test_ingest_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        assert all(f.source_tool == "acunetix" for f in findings)

    def test_ingest_affected_hosts(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        by_title = {f.title: f for f in findings}
        assert "www.itsecgames.com" in by_title["Slow HTTP Denial of Service Attack"].affected_hosts

    def test_ingest_csp_finding_is_info(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "acunetix_real.xml")
        by_title = {f.title: f for f in findings}
        assert by_title["Content Security Policy (CSP) not implemented"].severity == Severity.INFO
