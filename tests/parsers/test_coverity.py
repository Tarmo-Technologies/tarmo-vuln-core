"""Unit tests for the Coverity JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.coverity import CoverityIngestor
from tarmo_vuln_core.models import Finding, Severity

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
