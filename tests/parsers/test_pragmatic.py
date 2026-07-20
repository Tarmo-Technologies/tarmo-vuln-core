"""Unit tests for the Pragmatic CSV ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.pragmatic import PragmaticIngestor

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestPragmaticIngestor:
    def setup_method(self) -> None:
        self.ingestor = PragmaticIngestor()

    def test_can_handle_pragmatic(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "pragmatic_sample.csv") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.csv") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.csv")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        assert all(f.source_tool == "pragmatic" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        assert all(f.id.startswith("pragmatic-") for f in findings)

    def test_array_bounds_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        ab = [f for f in findings if f.title == "array_bounds"][0]
        assert ab.cwe_id == 119

    def test_null_deref_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        nd = [f for f in findings if f.title == "null_deref"][0]
        assert nd.cwe_id == 476

    def test_language_is_ada(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        assert all(f.extra_fields.get("language") == "Ada" for f in findings)

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pragmatic_sample.csv")
        ab = [f for f in findings if f.title == "array_bounds"][0]
        assert ab.source_code_refs[0].file_path == "src/buffer.adb"
        assert ab.source_code_refs[0].start_line == 120
