"""Unit tests for the Coverity JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.coverity import CoverityIngestor
from tarmo_vuln_core.models import Severity

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
