"""Unit tests for the ESLint JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.eslint import EslintIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestEslintIngestor:
    def setup_method(self) -> None:
        self.ingestor = EslintIngestor()

    def test_can_handle_eslint(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "coverity_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        assert all(f.source_tool == "eslint" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        assert all(f.id.startswith("eslint-") for f in findings)

    def test_error_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        no_undef = [f for f in findings if f.title == "no-undef"][0]
        assert no_undef.severity == Severity.MEDIUM

    def test_warning_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        unused = [f for f in findings if f.title == "no-unused-vars"][0]
        assert unused.severity == Severity.LOW

    def test_message_in_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        no_undef = [f for f in findings if f.title == "no-undef"][0]
        assert "'fetch' is not defined." in no_undef.description

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "eslint_sample.json")
        no_undef = [f for f in findings if f.title == "no-undef"][0]
        assert no_undef.source_code_refs[0].file_path == "/src/app/utils.js"
        assert no_undef.source_code_refs[0].start_line == 15
