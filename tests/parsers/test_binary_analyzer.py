"""Unit tests for the binary strings and binwalk ingestors."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.binary_analyzer import BinwalkIngestor, StringsIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestStringsIngestor:
    def setup_method(self) -> None:
        self.ingestor = StringsIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_strings_file(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "firmware.elf.strings") is True

    def test_cannot_handle_binwalk(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "firmware_binwalk.txt") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.strings") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.strings")

    # -- Finding correctness tests -----------------------------------------------

    def test_detects_urls(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "hardcoded-url" in by_ref

    def test_detects_emails(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "hardcoded-email" in by_ref

    def test_detects_api_key(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "api-key-pattern" in by_ref
        assert by_ref["api-key-pattern"].severity == Severity.HIGH

    def test_detects_connection_string(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "connection-string" in by_ref

    def test_detects_private_key(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "private-key-marker" in by_ref
        assert by_ref["private-key-marker"].severity == Severity.CRITICAL

    def test_detects_password(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert "password-assignment" in by_ref

    def test_source_tool_is_strings(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        assert all(f.source_tool == "strings" for f in findings)

    def test_secrets_redacted_in_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware.elf.strings")
        for f in findings:
            # Full API key should not appear in description
            assert "AKIA1234567890ABCDEF" not in f.description


@pytest.mark.unit
class TestBinwalkIngestor:
    def setup_method(self) -> None:
        self.ingestor = BinwalkIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_binwalk_txt(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "firmware_binwalk.txt") is True

    def test_cannot_handle_strings_file(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "firmware.elf.strings") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.binwalk") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.binwalk")

    # -- Finding correctness tests -----------------------------------------------

    def test_detects_embedded_certificate(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        by_ref = {f.raw_ref: f for f in findings}
        assert "embedded-certificate" in by_ref

    def test_detects_embedded_private_key(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        by_ref = {f.raw_ref: f for f in findings}
        assert "embedded-private-key" in by_ref
        assert by_ref["embedded-private-key"].severity == Severity.CRITICAL

    def test_detects_embedded_filesystem(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        by_ref = {f.raw_ref: f for f in findings}
        assert "embedded-filesystem" in by_ref

    def test_detects_debug_symbols(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        by_ref = {f.raw_ref: f for f in findings}
        assert "debug-symbols" in by_ref

    def test_source_tool_is_binwalk(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        assert all(f.source_tool == "binwalk" for f in findings)

    def test_id_prefix_is_binwalk(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "firmware_binwalk.txt")
        assert all(f.id.startswith("binwalk-") for f in findings)
