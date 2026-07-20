"""Unit tests for the Nexpose XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.nexpose import NexposeIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestNexposeIngestor:
    def setup_method(self) -> None:
        self.ingestor = NexposeIngestor()

    # -- can_handle() ---------------------------------------------------------

    def test_can_handle_nexpose(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nexpose_real.xml") is True

    def test_cannot_handle_wrong_format(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    # -- ingest() error handling ----------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    # -- Finding correctness --------------------------------------------------

    def test_ingest_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        assert len(findings) == 17

    def test_ingest_specific_field(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        by_id = {f.id: f for f in findings}
        assert (
            by_id["nexpose-tcp-seq-num-approximation"].title
            == "TCP Sequence Number Approximation Vulnerability"
        )

    def test_ingest_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        assert all(f.source_tool == "nexpose" for f in findings)

    def test_ingest_affected_host_192_168_1_1(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        by_id = {f.id: f for f in findings}
        assert "192.168.1.1" in by_id["nexpose-tcp-seq-num-approximation"].affected_hosts

    def test_ingest_ssh_default_password_critical(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        by_id = {f.id: f for f in findings}
        assert by_id["nexpose-ssh-default-account-root-password-root"].severity == Severity.CRITICAL

    def test_ingest_multiple_hosts_merged(self) -> None:
        """tcp-seq-num-approximation appears on 3 nodes and should merge hosts."""
        findings = self.ingestor.ingest(FIXTURES / "nexpose_real.xml")
        by_id = {f.id: f for f in findings}
        hosts = by_id["nexpose-tcp-seq-num-approximation"].affected_hosts
        assert len(hosts) == 3
        assert "192.168.1.1" in hosts
        assert "192.168.1.18" in hosts
        assert "192.168.1.33" in hosts
