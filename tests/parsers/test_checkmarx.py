"""Unit tests for the Checkmarx XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.models import Severity, SourceCodeRef

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


def _path_node(file: str, line: int, column: int, name: str, node_type: str | None) -> str:
    type_el = f"<Type>{node_type}</Type>" if node_type is not None else ""
    return (
        f"<PathNode><FileName>{file}</FileName><Line>{line}</Line><Column>{column}</Column>"
        f"<NodeId>1</NodeId><Name>{name}</Name>{type_el}</PathNode>"
    )


@pytest.mark.unit
class TestCheckmarxDataFlows:
    """PathNodes -> ``Finding.data_flows`` (#8); the PathNode refs and trace stay as they were."""

    def setup_method(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor

        self.ingestor = CheckmarxIngestor()
        findings = self.ingestor.ingest(FIXTURES / "checkmarx_sample.xml")
        self.sqli = next(f for f in findings if "SQL" in f.title)
        self.xss = next(f for f in findings if "XSS" in f.title)

    def test_path_nodes_become_one_flow_first_source_last_sink(self) -> None:
        [flow] = self.sqli.data_flows
        assert [
            (s.file_path, s.start_line, s.column, s.role, s.symbol, s.message, s.tool_kind)
            for s in flow.steps
        ] == [
            (
                "src/controllers/UserController.cs",
                42,
                15,
                "source",
                "username",
                "username",
                "MethodInvokeExpr",
            ),
            ("src/data/DbContext.cs", 88, 20, "sink", "Query", "Query", "MethodInvokeExpr"),
        ]
        assert {s.origin for s in flow.steps} == {"checkmarx_path"}
        assert flow.truncated is False

    def test_single_path_node_gives_no_flow(self) -> None:
        assert self.xss.data_flows == []

    def test_existing_refs_and_trace_unchanged(self) -> None:
        assert self.sqli.source_code_refs == [
            SourceCodeRef(
                file_path="src/controllers/UserController.cs",
                start_line=42,
                column=15,
                symbol="username",
                is_sink=False,
            ),
            SourceCodeRef(
                file_path="src/data/DbContext.cs", start_line=88, column=20, symbol="Query"
            ),
        ]
        assert self.sqli.affected_hosts == ["src/controllers/UserController.cs"]
        assert self.sqli.extra_fields == {
            "data_flow_trace": [
                {"file": "src/controllers/UserController.cs", "line": 42, "snippet": "username"},
                {"file": "src/data/DbContext.cs", "line": 88, "snippet": "Query"},
            ]
        }

    def test_each_path_element_is_its_own_flow(self, tmp_path: Path) -> None:
        report = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<CxXMLResults CheckmarxVersion="9.0">'
            '<Query cweId="89" name="SQL_Injection" Severity="High">'
            '<Result NodeId="7" FileName="src/a.cs" Line="12">'
            "<Path>"
            + _path_node("src/a.cs", 3, 5, "Request.QueryString[&quot;id&quot;]", "Param")
            + _path_node("src/a.cs", 12, 9, "ExecuteQuery", None)
            + "</Path><Path>"
            + _path_node("src/b.cs", 7, 1, "id", "Declarator")
            + _path_node("src/b.cs", 8, 2, "cmd.Text", "MemberAccess")
            + _path_node("src/a.cs", 12, 9, "ExecuteQuery", "MethodInvokeExpr")
            + "</Path></Result></Query></CxXMLResults>"
        )
        path = tmp_path / "cx.xml"
        path.write_text(report, encoding="utf-8")

        [f] = self.ingestor.ingest(path)

        assert [
            [(s.file_path, s.start_line, s.role, s.symbol, s.tool_kind) for s in flow.steps]
            for flow in f.data_flows
        ] == [
            [
                ("src/a.cs", 3, "source", None, "Param"),
                ("src/a.cs", 12, "sink", "ExecuteQuery", None),
            ],
            [
                ("src/b.cs", 7, "source", "id", "Declarator"),
                ("src/b.cs", 8, "step", "cmd.Text", "MemberAccess"),
                ("src/a.cs", 12, "sink", "ExecuteQuery", "MethodInvokeExpr"),
            ],
        ]
        assert f.data_flows[0].steps[0].message == 'Request.QueryString["id"]'
        # The merged trace and refs keep today's shape: every node, last one the sink.
        assert len(f.extra_fields["data_flow_trace"]) == 5
        assert [r.is_sink for r in f.source_code_refs] == [False, False, False, False, True]
