"""Unit tests for the configuration file security analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.config_analyzer import ConfigAnalyzerIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestConfigAnalyzerIngestor:
    def setup_method(self) -> None:
        self.ingestor = ConfigAnalyzerIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_env_file(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sample_config.env") is True

    def test_cannot_handle_json_yaml_xml(self) -> None:
        """Shared extensions (.json, .yaml, .xml) are NOT auto-detected."""
        assert self.ingestor.can_handle(FIXTURES / "bandit_real.json") is False
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False
        assert self.ingestor.can_handle(FIXTURES / "firmware.elf.strings") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.env") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.env")

    # -- Finding correctness tests -----------------------------------------------

    def test_detects_debug_mode(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "debug-mode-enabled" in by_ref
        assert by_ref["debug-mode-enabled"].severity == Severity.HIGH

    def test_detects_default_password(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "default-password" in by_ref

    def test_detects_cleartext_credential(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "cleartext-credential" in by_ref

    def test_detects_permissive_cors(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "permissive-cors" in by_ref
        assert by_ref["permissive-cors"].severity == Severity.MEDIUM

    def test_detects_insecure_tls(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "insecure-tls-config" in by_ref

    def test_detects_dev_url(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "dev-url-in-config" in by_ref

    def test_detects_verbose_errors(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "verbose-errors" in by_ref

    def test_detects_admin_endpoint(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        assert "exposed-admin-endpoint" in by_ref

    def test_source_tool_is_config_analyzer(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        assert all(f.source_tool == "config-analyzer" for f in findings)

    def test_source_code_refs_have_line_numbers(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        debug = by_ref["debug-mode-enabled"]
        assert len(debug.source_code_refs) >= 1
        assert debug.source_code_refs[0].start_line is not None
        assert debug.source_code_refs[0].start_line > 0

    def test_skips_commented_lines(self) -> None:
        """Commented-out SMTP_PASSWORD should not trigger a finding on its own."""
        findings = self.ingestor.ingest(FIXTURES / "sample_config.env")
        by_ref = {f.raw_ref: f for f in findings}
        # The cleartext credential finding should exist for the uncommented line
        cred = by_ref.get("cleartext-credential")
        if cred:
            # Ensure the commented line (with # prefix) is not in the refs
            for ref in cred.source_code_refs:
                # Line 22 is "# SMTP_PASSWORD=old_password_commented_out" — should not match
                assert ref.start_line != 22
