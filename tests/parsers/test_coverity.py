"""Unit tests for the Coverity JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.coverity import CoverityIngestor
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestCoverityIngestor:
    def setup_method(self) -> None:
        self.ingestor = CoverityIngestor()

    def test_can_handle_coverity(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "coverity_sample.json") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        assert all(f.source_tool == "coverity" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        assert all(f.id.startswith("coverity-") for f in findings)

    def test_null_returns_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        null_ret = [f for f in findings if f.title == "NULL_RETURNS"][0]
        assert null_ret.cwe_id == 476

    def test_null_returns_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        null_ret = [f for f in findings if f.title == "NULL_RETURNS"][0]
        assert null_ret.severity == Severity.HIGH

    def test_resource_leak_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        leak = [f for f in findings if f.title == "RESOURCE_LEAK"][0]
        assert leak.severity == Severity.MEDIUM

    def test_event_trace_in_extra_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        null_ret = [f for f in findings if f.title == "NULL_RETURNS"][0]
        trace = null_ret.extra_fields.get("event_trace")
        assert isinstance(trace, list)
        assert len(trace) == 2

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        null_ret = [f for f in findings if f.title == "NULL_RETURNS"][0]
        assert null_ret.source_code_refs[0].file_path == "/src/utils/parser.c"
        assert null_ret.source_code_refs[0].start_line == 105

    def test_cli_json_prefers_stripped_main_path(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_cli_sample.json")
        finding = findings[0]
        assert finding.source_code_refs[0].file_path == "IadeFt-IGhxEGm.yml"
        assert finding.source_code_refs[0].start_line == 5

    def test_cli_json_uses_public_schema_fields(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_cli_sample.json")
        finding = findings[0]
        assert finding.cwe_id == 552
        assert "root filesystem" in finding.description
        assert finding.extra_fields["event_trace"][0]["eventDescription"].startswith(
            "The docker service container is configured"
        )

    def test_function_display_name_becomes_symbol(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        null_ret = [f for f in findings if f.title == "NULL_RETURNS"][0]
        assert null_ret.source_code_refs[0].symbol == "parse_config"

    def test_null_function_display_name_leaves_symbol_unset(self) -> None:
        [finding] = self.ingestor.ingest(FIXTURES / "coverity_cli_sample.json")
        assert finding.source_code_refs[0].symbol is None


@pytest.mark.unit
class TestCoverityGeneratedCode:
    """Stripped build paths, functionDisplayName and event-path normalization."""

    def setup_method(self) -> None:
        self.ingestor = CoverityIngestor()

    def _v10(self, title: str) -> Finding:
        findings = self.ingestor.ingest(FIXTURES / "coverity_generated_v10.json")
        assert len(findings) == 2
        return next(f for f in findings if f.title == title)

    def test_v10_generated_file_uses_stripped_path_and_symbol(self) -> None:
        f = self._v10("OVERRUN")
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.start_line, ref.symbol) == (
            "build/gen/foo_idl.c",
            212,
            "foo_idl_unmarshal_request",
        )
        assert f.cwe_id == 119

    def test_v10_records_unstripped_path_and_derived_strip_prefix(self) -> None:
        f = self._v10("OVERRUN")
        assert f.extra_fields["resolved_path"] == "/home/ci/work/build/gen/foo_idl.c"
        assert f.extra_fields["strip_prefix"] == "/home/ci/work/"

    def test_v10_event_paths_are_normalized(self) -> None:
        f = self._v10("OVERRUN")
        trace = f.extra_fields["event_trace"]
        assert [e["file_path"] for e in trace] == [
            "build/gen/foo_idl.c",
            "build/gen/foo_idl.c",
            # No strippedFilePathname on this event: the main event's strip prefix applies.
            "src/foo_server.c",
        ]
        # The raw Coverity fields stay intact for audit.
        assert trace[2]["filePathname"] == "/home/ci/work/src/foo_server.c"

    def test_v10_raw_events_are_not_mutated(self) -> None:
        raw = json.loads((FIXTURES / "coverity_generated_v10.json").read_text())
        self.ingestor.ingest(FIXTURES / "coverity_generated_v10.json")
        assert "file_path" not in raw["issues"][0]["events"][0]

    def test_v10_in_source_issue_symbol(self) -> None:
        f = self._v10("RESOURCE_LEAK")
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.symbol) == ("src/foo_server.c", "load_config")

    def test_v7_unstripped_absolute_path_kept_verbatim(self) -> None:
        [f] = self.ingestor.ingest(FIXTURES / "coverity_generated_v7.json")
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.start_line, ref.symbol) == (
            "/tmp/ci-7f3e2a/build/gen/foo_idl.c",
            219,
            "foo_idl_unmarshal_request",
        )
        assert "strip_prefix" not in f.extra_fields
        assert "resolved_path" not in f.extra_fields
        assert f.extra_fields["event_trace"][0]["file_path"] == "/tmp/ci-7f3e2a/build/gen/foo_idl.c"

    def test_same_defect_across_builds_shares_symbol(self) -> None:
        # Regenerated output shifts lines (212 -> 219) and the build root differs;
        # the function symbol is the stable anchor downstream identity can use.
        new = self._v10("OVERRUN")
        [old] = self.ingestor.ingest(FIXTURES / "coverity_generated_v7.json")
        assert new.source_code_refs[0].symbol == old.source_code_refs[0].symbol
        assert new.source_code_refs[0].start_line != old.source_code_refs[0].start_line

    def test_merge_key_recorded_for_downstream_identity(self) -> None:
        """Coverity's mergeKey is stable across builds and line shifts."""
        new = self._v10("OVERRUN")
        [old] = self.ingestor.ingest(FIXTURES / "coverity_generated_v7.json")
        assert new.extra_fields["merge_key"] == "0b8f5c2d9e41a7c3f6d2e8a1b4c7d9e2"
        assert old.extra_fields["merge_key"] == new.extra_fields["merge_key"]
        assert self._v10("RESOURCE_LEAK").extra_fields["merge_key"] == (
            "5e2a9c1f7b3d4e6a8c0f2b4d6e8a1c3f"
        )


def _event(line: int, tag: str, *, main: bool = False, remediation: bool = False) -> dict:
    return {
        "eventDescription": f"{tag} at {line}",
        "eventNumber": line,
        "eventTag": tag,
        "filePathname": "/home/ci/work/src/big.c",
        "strippedFilePathname": "src/big.c",
        "lineNumber": line,
        "main": main,
        "remediation": remediation,
        "events": None,
    }


def _write_issue(tmp_path: Path, events: list[dict]) -> Path:
    issue = {
        "mergeKey": "k1",
        "checkerName": "TAINTED_SCALAR",
        "mainEventFilePathname": "/home/ci/work/src/big.c",
        "strippedMainEventFilePathname": "src/big.c",
        "mainEventLineNumber": 31,
        "checkerProperties": {"impact": "High", "cweCategory": "20"},
        "events": events,
    }
    path = tmp_path / "cov.json"
    path.write_text(json.dumps({"formatVersion": 10, "issues": [issue]}))
    return path


@pytest.mark.unit
class TestCoverityDataFlows:
    """Coverity ``events`` -> ``Finding.data_flows`` (#8); ``event_trace`` is unchanged."""

    def setup_method(self) -> None:
        self.ingestor = CoverityIngestor()

    def _v10(self, title: str) -> Finding:
        findings = self.ingestor.ingest(FIXTURES / "coverity_generated_v10.json")
        return next(f for f in findings if f.title == title)

    def test_main_event_is_the_sink_and_the_others_are_steps(self) -> None:
        [flow] = self._v10("OVERRUN").data_flows
        assert [(s.file_path, s.start_line, s.role, s.tool_kind) for s in flow.steps] == [
            ("build/gen/foo_idl.c", 205, "step", "assignment"),
            # Paths are normalized like event_trace's file_path.
            ("src/foo_server.c", 88, "step", "caller"),
            ("build/gen/foo_idl.c", 212, "sink", "overrun-buffer-arg"),
        ]
        assert flow.steps[0].message == (
            'Assigning: "len" = "hdr->name_len". '
            'The value of "len" is now between 0 and 65535 (inclusive).'
        )
        assert {s.origin for s in flow.steps} == {"coverity_event"}
        assert [s.symbol for s in flow.steps] == [None, None, None]
        assert flow.truncated is False

    def test_event_trace_and_refs_unchanged(self) -> None:
        f = self._v10("OVERRUN")
        assert set(f.extra_fields) == {"event_trace", "resolved_path", "strip_prefix", "merge_key"}
        assert [
            (e["eventNumber"], e["eventTag"], e["main"], e["file_path"])
            for e in f.extra_fields["event_trace"]
        ] == [
            (1, "assignment", False, "build/gen/foo_idl.c"),
            (2, "overrun-buffer-arg", True, "build/gen/foo_idl.c"),
            (3, "caller", False, "src/foo_server.c"),
        ]
        assert f.source_code_refs == [
            SourceCodeRef(
                file_path="build/gen/foo_idl.c", start_line=212, symbol="foo_idl_unmarshal_request"
            )
        ]

    def test_single_event_issue_has_no_flow(self) -> None:
        assert self._v10("RESOURCE_LEAK").data_flows == []

    def test_remediation_event_is_not_a_step(self) -> None:
        # Main event plus a remediation event: no path beyond the sink.
        [f] = self.ingestor.ingest(FIXTURES / "coverity_cli_sample.json")
        assert f.data_flows == []
        assert len(f.extra_fields["event_trace"]) == 2

    def test_events_without_a_main_flag_give_no_flow(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "coverity_sample.json")
        assert [f.data_flows for f in findings] == [[], []]

    def test_long_event_list_keeps_the_main_event(self, tmp_path: Path) -> None:
        events = [_event(n, "taint", main=(n == 31)) for n in range(1, 51)]
        events.append(_event(51, "remediation", remediation=True))

        [f] = self.ingestor.ingest(_write_issue(tmp_path, events))

        [flow] = f.data_flows
        assert flow.truncated is True
        # 49 steps + the main event = 50: the first 16 and the last 16, main last.
        assert [s.start_line for s in flow.steps] == (
            list(range(1, 17)) + list(range(36, 51)) + [31]
        )
        assert flow.steps[-1].role == "sink"
        assert {s.role for s in flow.steps[:-1]} == {"step"}
        # event_trace keeps today's first-5-plus-last-5 trim.
        assert [e["lineNumber"] for e in f.extra_fields["event_trace"]] == [
            1,
            2,
            3,
            4,
            5,
            47,
            48,
            49,
            50,
            51,
        ]

    def test_nested_events_are_steps_in_tree_order(self, tmp_path: Path) -> None:
        outer = _event(10, "call")
        outer["events"] = [_event(20, "assignment"), _event(21, "alias")]
        [f] = self.ingestor.ingest(_write_issue(tmp_path, [outer, _event(31, "sink", main=True)]))

        assert [(s.start_line, s.tool_kind, s.role) for s in f.data_flows[0].steps] == [
            (10, "call", "step"),
            (20, "assignment", "step"),
            (21, "alias", "step"),
            (31, "sink", "sink"),
        ]
