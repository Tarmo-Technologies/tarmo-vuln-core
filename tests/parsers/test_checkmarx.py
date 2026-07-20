"""Unit tests for the Checkmarx XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestCheckmarxIngestor:
    def setup_method(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor

        self.ingestor = CheckmarxIngestor()

    def test_can_handle_checkmarx_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "checkmarx_sample.xml") is True

    def test_cannot_handle_cppcheck_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "cppcheck_real.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        assert all(f.source_tool == "checkmarx" for f in findings)

    def test_sql_injection_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.cwe_id == 89

    def test_sql_injection_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.severity == Severity.HIGH

    def test_sql_injection_file_path(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.source_code_refs[0].file_path == "src/controllers/UserController.cs"

    def test_sql_injection_line_number(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.source_code_refs[0].start_line == 42

    def test_data_flow_trace_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        trace = sqli.extra_fields.get("data_flow_trace")
        assert isinstance(trace, list)
        assert len(trace) == 2
        assert trace[0]["file"] == "src/controllers/UserController.cs"
        assert trace[0]["line"] == 42

    def test_xss_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        xss = [f for f in findings if "XSS" in f.title][0]
        assert xss.cwe_id == 79

    def test_sql_injection_sink_and_taint_sources(self) -> None:
        """Multi-PathNode findings: last PathNode is sink, prior nodes are taint sources."""
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        sqli = [f for f in findings if "SQL" in f.title][0]
        sinks = [r for r in sqli.source_code_refs if r.is_sink]
        sources = [r for r in sqli.source_code_refs if not r.is_sink]
        # Exactly one sink — the final PathNode at DbContext.cs:88.
        assert len(sinks) == 1
        assert sinks[0].file_path == "src/data/DbContext.cs"
        assert sinks[0].start_line == 88
        assert sinks[0].column == 20
        assert sinks[0].symbol == "Query"
        # One taint source — the earlier PathNode at UserController.cs:42.
        assert len(sources) == 1
        assert sources[0].file_path == "src/controllers/UserController.cs"
        assert sources[0].start_line == 42
        assert sources[0].column == 15
        assert sources[0].symbol == "username"

    def test_xss_single_pathnode_is_sink(self) -> None:
        """Single-PathNode findings collapse to sink-only (no taint_sources)."""
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        xss = [f for f in findings if "XSS" in f.title][0]
        sinks = [r for r in xss.source_code_refs if r.is_sink]
        sources = [r for r in xss.source_code_refs if not r.is_sink]
        assert len(sinks) == 1
        assert sinks[0].file_path == "src/views/SearchView.cs"
        assert sinks[0].start_line == 23
        assert sinks[0].column == 10
        assert sinks[0].symbol == "searchTerm"
        assert sources == []
