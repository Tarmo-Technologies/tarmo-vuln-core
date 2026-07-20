"""Unit tests for the Sigasi JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.sigasi import SigasiIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestSigasiIngestor:
    def setup_method(self) -> None:
        self.ingestor = SigasiIngestor()

    def test_can_handle_sigasi(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sigasi_sample.json") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        assert len(findings) == 3

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        assert all(f.source_tool == "sigasi" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        assert all(f.id.startswith("sigasi-") for f in findings)

    def test_error_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        errors = [f for f in findings if f.severity == Severity.HIGH]
        assert len(errors) == 2

    def test_warning_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        warnings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(warnings) == 1

    def test_title_contains_language_and_code(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        first = findings[0]
        assert first.title == "vhdl:1"

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sigasi_sample.json")
        first = findings[0]
        assert first.source_code_refs[0].file_path == "src/top_level.vhd"
        assert first.source_code_refs[0].start_line == 45
