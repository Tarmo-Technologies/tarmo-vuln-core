"""Unit tests for the Semgrep SARIF ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.semgrep import SemgrepIngestor

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestSemgrepIngestor:
    def setup_method(self) -> None:
        self.ingestor = SemgrepIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_semgrep_sarif(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "semgrep_real.sarif") is True

    def test_cannot_handle_generic_sarif(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sarif_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.sarif") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.sarif")

    # -- Finding correctness tests -----------------------------------------------

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        assert len(findings) == 6

    def test_source_tool_is_semgrep(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        assert all(f.source_tool == "semgrep" for f in findings)

    def test_id_prefix_is_semgrep(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        assert all(f.id.startswith("semgrep-") for f in findings)

    def test_specific_rule_dangerous_exec_command(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        refs = [f.raw_ref for f in findings]
        assert any("dangerous-exec-command" in (r or "") for r in refs)

    def test_cwe_extracted_from_tags(self) -> None:
        """Semgrep tags use format 'CWE-94: Description' — parser must extract CWE ID."""
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        by_ref = {f.raw_ref: f for f in findings}
        # dangerous-exec-command rule has tag "CWE-94: ..."
        exec_finding = by_ref.get(
            "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"
        )
        assert exec_finding is not None
        assert exec_finding.cwe_id == 94

    def test_cwe_populated_for_all_security_rules(self) -> None:
        """All rules in the real fixture have CWE tags — none should be None."""
        findings = self.ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        for f in findings:
            assert f.cwe_id is not None, f"CWE missing for rule {f.raw_ref}"
