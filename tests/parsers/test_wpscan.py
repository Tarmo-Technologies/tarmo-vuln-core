"""Unit tests for the WPScan JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.wpscan import WpscanIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestWpscanIngestor:
    def setup_method(self) -> None:
        self.ingestor = WpscanIngestor()

    # -- can_handle() ---------------------------------------------------------

    def test_can_handle_wpscan(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "wpscan_real.json") is True

    def test_cannot_handle_wrong_format(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    # -- ingest() error handling ----------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    # -- Finding correctness --------------------------------------------------

    def test_ingest_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        assert len(findings) == 9

    def test_ingest_specific_field(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        expected = (
            "WordPress 3.6.0-4.7.2 - Authenticated Cross-Site Scripting"
            " (XSS) via Media File Metadata"
        )
        assert by_id["wpscan-cve-2017-6814"].title == expected

    def test_ingest_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        assert all(f.source_tool == "wpscan" for f in findings)

    def test_ingest_affected_host(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        assert all("http://www.redacted.com" in f.affected_hosts for f in findings)

    def test_ingest_xmlrpc_synthetic_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        xmlrpc = by_id["wordpress-xmlrpc-enabled"]
        assert xmlrpc.title == "WordPress XML-RPC Enabled"
        assert xmlrpc.severity == Severity.MEDIUM

    def test_ingest_readme_synthetic_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        readme = by_id["wordpress-readme-exposed"]
        assert readme.title == "WordPress readme.html Accessible"
        assert readme.severity == Severity.INFO

    def test_ingest_outdated_core_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        core = by_id["wordpress-outdated-core"]
        assert core.title == "WordPress Core 4.7.2 (Insecure)"
        assert core.severity == Severity.MEDIUM

    def test_ingest_user_enumeration_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        users = by_id["wordpress-user-enumeration"]
        assert "marie" in users.description
        assert users.severity == Severity.INFO

    def test_ingest_cve_raw_ref(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "wpscan_real.json")
        by_id = {f.id: f for f in findings}
        assert by_id["wpscan-cve-2017-6814"].raw_ref == "CVE-2017-6814"
