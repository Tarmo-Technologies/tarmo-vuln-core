"""Unit tests for the SARP CSV ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.sarp import SarpIngestor, SarpSchemaError
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestSarpIngestor:
    def setup_method(self) -> None:
        self.ingestor = SarpIngestor()

    def test_can_handle_sarp(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sarp_sample.csv") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.csv") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.csv")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        assert len(findings) == 3

    def test_source_tool(self) -> None:
        """Source tool comes from Scanner column."""
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        scanners = {f.source_tool for f in findings}
        assert "checkmarx" in scanners
        assert "cppcheck" in scanners

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        assert all(f.id.startswith("sarp-") for f in findings)

    def test_sql_injection_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.cwe_id == 89

    def test_buffer_overflow_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        bo = [f for f in findings if f.title == "Buffer Overflow"][0]
        assert bo.severity == Severity.CRITICAL

    def test_xss_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        xss = [f for f in findings if f.title == "Cross-Site Scripting"][0]
        assert xss.severity == Severity.MEDIUM

    def test_remediation_from_proposed_mitigation(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.remediation == "Use parameterized queries"

    def test_confidence_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.extra_fields["cdata_confidence"] == "Confirmed"

    def test_exploit_maturity_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.extra_fields["exploit_maturity"] == "proof_of_concept"

    def test_cvss_vector(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.cvss_vector == "AV:N/AC:L/PR:N/UI:N"

    def test_raw_ref_is_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.raw_ref == "Checkmarx SAST"

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.source_code_refs[0].file_path == "src/auth/login.java"
        assert sqli.source_code_refs[0].start_line == 42

    def test_language_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.extra_fields["language"] == "Java"

    def test_symbol_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarp_sample.csv")
        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.extra_fields["symbol"] == "buildQuery"

    def test_missing_required_column_raises_sarp_schema_error(self, tmp_path: Path) -> None:
        """Dropping the required Path column must raise SarpSchemaError."""
        csv_body = "ID,Type,Scanner,Tool Severity\n1,SQL Injection,checkmarx,High\n"
        csv_path = tmp_path / "missing_path.csv"
        csv_path.write_text(csv_body)

        with pytest.raises(SarpSchemaError) as exc_info:
            self.ingestor.ingest(csv_path)

        assert exc_info.value.missing_required == ["Path"]
        assert set(exc_info.value.expected_required) == {
            "ID",
            "Path",
            "Type",
            "Scanner",
            "Tool Severity",
        }
        assert "DestPath" in exc_info.value.expected_optional
        assert "CWE" in exc_info.value.expected_optional

    def test_unknown_column_warns_and_does_not_fail(self, tmp_path: Path) -> None:
        """Headers with extra columns should succeed but record the unknowns."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,NotARealColumn\n"
            "1,src/x.py,SQL Injection,checkmarx,High,surprise\n"
        )
        csv_path = tmp_path / "unknown_col.csv"
        csv_path.write_text(csv_body)

        with pytest.warns(UserWarning, match="unrecognized columns"):
            findings = self.ingestor.ingest(csv_path)

        assert len(findings) == 1
        assert self.ingestor.last_unknown_columns == ["NotARealColumn"]

    def test_cwe_column_overrides_tool_cwe(self, tmp_path: Path) -> None:
        """When CWE is present, it wins; Tool CWE is preserved in extra_fields."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,Tool CWE,CWE\n"
            "1,src/auth.py,SQLi,checkmarx,High,20,89\n"
        )
        csv_path = tmp_path / "cwe.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert len(findings) == 1
        assert findings[0].cwe_id == 89
        assert findings[0].extra_fields["tool_cwe"] == "20"

    def test_tool_cwe_alone_still_sets_cwe_id(self, tmp_path: Path) -> None:
        """Back-compat: CSVs without CWE column keep existing behavior."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,Tool CWE\n1,src/auth.py,SQLi,checkmarx,High,89\n"
        )
        csv_path = tmp_path / "tool_cwe_only.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert findings[0].cwe_id == 89
        assert "tool_cwe" not in findings[0].extra_fields

    def test_dest_columns_produce_sink_and_source_refs(self, tmp_path: Path) -> None:
        """Dest* present → emit 2 refs: source (is_sink=False) + sink (is_sink=True)."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,Line,Symbol,"
            "DestPath,DestLine,DestSymbol\n"
            "1,src/input.py,SQLi,checkmarx,High,10,get_input,"
            "src/db.py,55,execute_query\n"
        )
        csv_path = tmp_path / "dest.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert len(findings) == 1

        refs = findings[0].source_code_refs
        assert len(refs) == 2

        source_ref = next(r for r in refs if not r.is_sink)
        assert source_ref.file_path == "src/input.py"
        assert source_ref.start_line == 10
        assert source_ref.symbol == "get_input"

        sink_ref = next(r for r in refs if r.is_sink)
        assert sink_ref.file_path == "src/db.py"
        assert sink_ref.start_line == 55
        assert sink_ref.symbol == "execute_query"

    def test_no_dest_columns_keeps_single_sink_ref(self, tmp_path: Path) -> None:
        """Back-compat: rows without Dest* keep the existing single-ref behavior."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,Line,Symbol\n"
            "1,src/x.py,SQLi,checkmarx,High,42,handler\n"
        )
        csv_path = tmp_path / "no_dest.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        refs = findings[0].source_code_refs
        assert len(refs) == 1
        assert refs[0].file_path == "src/x.py"
        assert refs[0].start_line == 42
        assert refs[0].symbol == "handler"
        assert refs[0].is_sink is True  # default

    def test_combined_fixture_smoke(self) -> None:
        """Combined fixture: row 1 has sink+source, row 2 does not."""
        findings = self.ingestor.ingest(FIXTURES / "sarp_combined_sample.csv")
        assert len(findings) == 2

        sqli = [f for f in findings if f.title == "SQL Injection"][0]
        assert sqli.cwe_id == 89
        assert sqli.extra_fields["tool_cwe"] == "20"
        sink_refs = [r for r in sqli.source_code_refs if r.is_sink]
        source_refs = [r for r in sqli.source_code_refs if not r.is_sink]
        assert len(sink_refs) == 1
        assert len(source_refs) == 1
        assert sink_refs[0].file_path == "src/db/session.py"
        assert sink_refs[0].start_line == 58
        assert source_refs[0].file_path == "src/api/login.py"

        xss = [f for f in findings if f.title == "XSS"][0]
        assert len([r for r in xss.source_code_refs if r.is_sink]) == 1
        assert len([r for r in xss.source_code_refs if not r.is_sink]) == 0

    def test_whitespace_cwe_falls_back_to_tool_cwe(self, tmp_path: Path) -> None:
        """A whitespace-only CWE cell must fall back to Tool CWE, not silently drop cwe_id."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,Tool CWE,CWE\n1,src/x.py,SQLi,checkmarx,High,89, \n"
        )
        csv_path = tmp_path / "ws_cwe.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert findings[0].cwe_id == 89
        assert "tool_cwe" not in findings[0].extra_fields

    def test_dest_line_without_dest_path_and_no_file_path_skips_sink(self, tmp_path: Path) -> None:
        """If no sink path can be constructed, no malformed sink ref is emitted."""
        csv_body = "ID,Path,Type,Scanner,Tool Severity,DestLine\n1,,SQLi,checkmarx,High,55\n"
        csv_path = tmp_path / "no_sink_path.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        # No first ref (file_path empty) and no second ref (dest_path empty + file_path empty)
        assert findings[0].source_code_refs == []

    def test_whitespace_line_cell_still_parses_as_int(self, tmp_path: Path) -> None:
        """Whitespace-padded Line cells must still produce a numeric line, not None."""
        csv_body = "ID,Path,Type,Scanner,Tool Severity,Line\n1,src/x.py,SQLi,checkmarx,High, 42 \n"
        csv_path = tmp_path / "ws_line.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert findings[0].source_code_refs[0].start_line == 42

    def test_whitespace_dest_line_still_parses_as_int(self, tmp_path: Path) -> None:
        """Whitespace-padded DestLine cells must still produce a numeric sink line."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,DestPath,DestLine\n"
            "1,src/src.py,SQLi,checkmarx,High,src/sink.py, 99 \n"
        )
        csv_path = tmp_path / "ws_dest_line.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        sink = next(r for r in findings[0].source_code_refs if r.is_sink)
        assert sink.start_line == 99

    def test_whitespace_only_dest_path_does_not_create_malformed_sink(self, tmp_path: Path) -> None:
        """A DestPath cell of pure whitespace must not produce a sink ref with empty file_path."""
        csv_body = (
            "ID,Path,Type,Scanner,Tool Severity,DestPath,DestLine\n1,,SQLi,checkmarx,High,   ,55\n"
        )
        csv_path = tmp_path / "ws_only_dest.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        # Both file_path and dest_path are whitespace-only; no ref should be emitted.
        assert findings[0].source_code_refs == []

    def test_whitespace_severity_still_maps(self, tmp_path: Path) -> None:
        """Whitespace-padded severity must still map correctly, not silently fall to MEDIUM."""
        csv_body = "ID,Path,Type,Scanner,Tool Severity\n1,src/x.py,SQLi,checkmarx, Critical \n"
        csv_path = tmp_path / "ws_sev.csv"
        csv_path.write_text(csv_body)

        findings = self.ingestor.ingest(csv_path)
        assert findings[0].severity == Severity.CRITICAL

    def test_schema_error_reports_both_missing_and_unknown_columns(self, tmp_path: Path) -> None:
        """When a header is missing a required col AND has a typo'd unknown col,
        the error must report both so the analyst can fix everything in one pass."""
        csv_body = (
            "ID,Type,Scanner,Tool Severity,Checker\n"  # missing 'Path', extra 'Checker'
            "1,SQLi,checkmarx,High,tainted-flow\n"
        )
        csv_path = tmp_path / "missing_and_unknown.csv"
        csv_path.write_text(csv_body)

        with pytest.raises(SarpSchemaError) as exc_info:
            self.ingestor.ingest(csv_path)

        assert exc_info.value.missing_required == ["Path"]
        assert exc_info.value.unknown_columns == ["Checker"]
