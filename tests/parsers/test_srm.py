"""Unit tests for the SRM XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.srm import SrmIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestSrmIngestor:
    def setup_method(self) -> None:
        self.ingestor = SrmIngestor()

    def test_can_handle_srm(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "srm_sample.xml") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        assert len(findings) == 3

    def test_source_tool(self) -> None:
        """Source tool is per-finding from the XML tool element."""
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        tools = {f.source_tool for f in findings}
        assert "checkmarx" in tools
        assert "fortify" in tools

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        assert all(f.id.startswith("srm-") for f in findings)

    def test_sql_injection_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.cwe_id == 89

    def test_xss_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        xss = [f for f in findings if f.title == "Cross-Site Scripting"][0]
        assert xss.severity == Severity.MEDIUM

    def test_cross_scanner_dedup(self) -> None:
        """Second SQL Injection from fortify (same type+file+line) should be marked duplicate."""
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        fortify_sqli = [
            f for f in findings if f.title == "SQL Injection" and f.source_tool == "fortify"
        ][0]
        assert "duplicate_of" in fortify_sqli.extra_fields

    def test_first_finding_not_duplicate(self) -> None:
        """First SQL Injection from checkmarx should NOT be marked duplicate."""
        findings = self.ingestor.ingest(FIXTURES / "srm_sample.xml")
        checkmarx_sqli = [
            f for f in findings if f.title == "SQL Injection" and f.source_tool == "checkmarx"
        ][0]
        assert "duplicate_of" not in checkmarx_sqli.extra_fields

    def test_missing_cwe_can_fall_back_to_srm_cdata(self, tmp_path: Path) -> None:
        report = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <findings>
    <finding id="SRM-1" type="Dead Code" severity="Info" cwe="">
      <tool name="CppCheck 2.18.0"/>
      <file path="src/main.c" line="12"/>
      <description>Dead branch remains</description>
    </finding>
  </findings>
</report>
"""
        path = tmp_path / "srm_missing_cwe.xml"
        path.write_text(report, encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 561
        assert findings[0].extra_fields.get("cdata_confidence") == "Inform"
