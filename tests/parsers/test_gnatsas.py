"""Unit tests for the GNAT SAS SARIF ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.gnatsas import GnatSasIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestGnatSasIngestor:
    def setup_method(self) -> None:
        self.ingestor = GnatSasIngestor()

    def test_can_handle_gnatsas(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "gnatsas_sample.sarif") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_generic_sarif(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sarif_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.sarif") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.sarif")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        assert all(f.source_tool == "gnatsas" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        assert all(f.id.startswith("gnatsas-") for f in findings)

    def test_buffer_overflow_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        bo = [f for f in findings if "buffer-overflow" in f.id][0]
        assert bo.severity == Severity.HIGH

    def test_range_check_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        rc = [f for f in findings if "range-check" in f.id][0]
        assert rc.severity == Severity.MEDIUM

    def test_ada_language_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        assert all(f.extra_fields.get("language") == "Ada" for f in findings)

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gnatsas_sample.sarif")
        bo = [f for f in findings if "buffer-overflow" in f.id][0]
        assert bo.source_code_refs[0].file_path == "src/comms.adb"
        assert bo.source_code_refs[0].start_line == 142
