"""Unit tests for the Fortify FPR ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.fortify import FortifyIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestFortifyIngestor:
    def setup_method(self) -> None:
        self.ingestor = FortifyIngestor()

    def test_can_handle_fortify(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "fortify_sample.fpr") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.fpr") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.fpr")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert all(f.source_tool == "fortify" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert all(f.id.startswith("fortify-") for f in findings)

    def test_sql_injection_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.severity == Severity.HIGH

    def test_xss_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        xss = [f for f in findings if "Cross-Site" in f.title][0]
        assert xss.severity == Severity.MEDIUM

    def test_sql_injection_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.cwe_id == 89

    def test_xss_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        xss = [f for f in findings if "Cross-Site" in f.title][0]
        assert xss.cwe_id == 79

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert len(sqli.source_code_refs) == 2
        assert sqli.source_code_refs[0].file_path == "src/db/query.java"
        assert sqli.source_code_refs[0].start_line == 45

    def test_can_handle_standalone_fvdl(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "fortify_realistic_sample.fvdl") is True

    def test_ingest_standalone_fvdl(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_realistic_sample.fvdl")
        assert len(findings) == 1
        assert findings[0].title == "Cross-Site Request Forgery"
        assert findings[0].source_code_refs[0].file_path == "public/category.html"
        assert findings[0].source_code_refs[0].start_line == 222

    def test_fvdl_without_rule_metadata_leaves_cwe_unset(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_realistic_sample.fvdl")
        assert findings[0].cwe_id is None
