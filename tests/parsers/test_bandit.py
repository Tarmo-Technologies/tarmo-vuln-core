"""Unit tests for the Bandit JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.bandit import BanditIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestBanditIngestor:
    def setup_method(self) -> None:
        self.ingestor = BanditIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_bandit_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "bandit_real.json") is True

    def test_cannot_handle_trivy_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "trivy_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    # -- Finding correctness tests -----------------------------------------------

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert len(findings) == 35

    def test_source_tool_is_bandit(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert all(f.source_tool == "bandit" for f in findings)

    def test_id_prefix_is_bandit(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert all(f.id.startswith("bandit-") for f in findings)

    def test_severity_b322_is_high(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b322 = [f for f in findings if f.raw_ref == "B322"]
        assert len(b322) > 0
        assert b322[0].severity == Severity.HIGH

    def test_severity_b608_is_medium(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b608 = [f for f in findings if f.raw_ref == "B608"]
        assert len(b608) > 0
        assert b608[0].severity == Severity.MEDIUM

    def test_b322_title_is_blacklist(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b322 = [f for f in findings if f.raw_ref == "B322"]
        assert b322[0].title == "blacklist"

    def test_source_code_refs_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert all(len(f.source_code_refs) == 1 for f in findings)

    def test_source_code_ref_file_path_matches_affected_host(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        for f in findings:
            assert f.source_code_refs[0].file_path == f.affected_hosts[0]

    def test_source_code_ref_has_start_line(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b322 = [f for f in findings if f.raw_ref == "B322"]
        assert b322[0].source_code_refs[0].start_line is not None
        assert b322[0].source_code_refs[0].start_line > 0

    def test_cwe_mapped_for_b322(self) -> None:
        """B322 (input) maps to CWE-78 (OS Command Injection)."""
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b322 = [f for f in findings if f.raw_ref == "B322"]
        assert len(b322) > 0
        assert b322[0].cwe_id == 78

    def test_cwe_mapped_for_b608(self) -> None:
        """B608 (hardcoded_sql_expressions) maps to CWE-89 (SQL Injection)."""
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        b608 = [f for f in findings if f.raw_ref == "B608"]
        assert len(b608) > 0
        assert b608[0].cwe_id == 89

    def test_source_code_ref_is_sink_default(self) -> None:
        """Single-ref Bandit findings are sinks — correlation anchors on them."""
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert all(f.source_code_refs[0].is_sink is True for f in findings)

    def test_source_code_ref_end_line_not_polluted_by_column(self) -> None:
        """end_line must not be populated from end_col_offset (fixes legacy bug)."""
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        # Bandit JSON does not emit line ranges or column offsets, so end_line
        # must stay None rather than holding a column value.
        for f in findings:
            ref = f.source_code_refs[0]
            assert ref.end_line is None, (
                f"end_line should be None, got {ref.end_line} (legacy col-offset bug)"
            )

    def test_column_stays_none_when_bandit_omits_it(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "bandit_real.json")
        assert all(f.source_code_refs[0].column is None for f in findings)
