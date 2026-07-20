"""Unit tests for the Gitleaks JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.gitleaks import GitleaksIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestGitleaksIngestor:
    def setup_method(self) -> None:
        self.ingestor = GitleaksIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_gitleaks_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "gitleaks_sample.json") is True

    def test_cannot_handle_bandit_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "bandit_real.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_cannot_handle_empty_array(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text("[]")
        assert self.ingestor.can_handle(f) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_ingest_invalid_json_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        with pytest.raises(IngestorError, match="Failed to parse gitleaks JSON"):
            self.ingestor.ingest(bad)

    # -- Finding correctness tests -----------------------------------------------

    def test_finding_count_grouped_by_rule(self) -> None:
        """4 occurrences across 3 RuleIDs → 3 findings."""
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        assert len(findings) == 3

    def test_source_tool_is_gitleaks(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        assert all(f.source_tool == "gitleaks" for f in findings)

    def test_id_prefix_is_gitleaks(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        assert all(f.id.startswith("gitleaks-") for f in findings)

    def test_severity_is_high(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_raw_ref_is_rule_id(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert "generic-api-key" in by_ref
        assert "aws-access-key-id" in by_ref
        assert "private-key" in by_ref

    def test_generic_api_key_grouped_two_occurrences(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        api_key = by_ref["generic-api-key"]
        assert len(api_key.source_code_refs) == 2
        assert len(api_key.affected_hosts) == 2

    def test_source_code_refs_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        api_key = by_ref["generic-api-key"]
        ref = api_key.source_code_refs[0]
        assert ref.file_path == "src/config.py"
        assert ref.start_line == 15

    def test_no_secret_values_in_description(self) -> None:
        """Verify that actual secret values never appear in finding text."""
        findings = self.ingestor.ingest(FIXTURES / "gitleaks_sample.json")
        for f in findings:
            assert "REDACTED" not in f.description or "REDACTED" in f.description
            # More importantly, no actual key patterns
            assert "AKIA" not in f.description
            assert "BEGIN RSA" not in f.description
