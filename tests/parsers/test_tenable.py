"""Unit tests for the Tenable.io JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.tenable import TenableIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestTenableIngestor:
    def setup_method(self) -> None:
        self.ingestor = TenableIngestor()

    # ── can_handle() tests ──────────────────────────────────────────────────

    def test_can_handle_tenable_sample(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "tenable_sample.json") is True

    def test_cannot_handle_trivy_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "trivy_sample.json") is False

    def test_cannot_handle_sarif_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sarif_sample.json") is False

    def test_cannot_handle_nmap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_cannot_handle_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        assert self.ingestor.can_handle(bad) is False

    def test_cannot_handle_json_without_vulnerabilities(self, tmp_path: Path) -> None:
        f = tmp_path / "other.json"
        f.write_text('{"data": []}')
        assert self.ingestor.can_handle(f) is False

    # ── ingest() error tests ────────────────────────────────────────────────

    def test_ingest_nonexistent_raises_ingestor_error(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_ingest_invalid_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        with pytest.raises(IngestorError, match="Failed to parse Tenable"):
            self.ingestor.ingest(bad)

    # ── Finding correctness tests ───────────────────────────────────────────

    def test_ingest_returns_four_findings(self) -> None:
        # 5 records but plugin 42873 is deduplicated across 2 hosts → 4 findings
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        assert len(findings) == 4

    def test_source_tool_is_tenable(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        assert all(f.source_tool == "tenable" for f in findings)

    def test_severity_mapping_medium(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["42873"].severity == Severity.MEDIUM

    def test_severity_mapping_low(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["65821"].severity == Severity.LOW

    def test_severity_mapping_info(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["10107"].severity == Severity.INFO

    def test_deduplication_multiple_hosts(self) -> None:
        # Plugin 42873 appears for both 10.0.0.1 and 10.0.0.2 → merged
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        hosts = by_plugin["42873"].affected_hosts
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts

    def test_title_from_plugin_name(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["42873"].title == "SSL Medium Strength Cipher Suites Supported (SWEET32)"

    def test_cvss3_score_preferred(self) -> None:
        # Plugin 42873 has cvss3_base_score=7.5
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["42873"].cvss_score == 7.5

    def test_cvss2_score_fallback(self) -> None:
        # Plugin 51192 has no cvss3 but has cvss2 = 6.4
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["51192"].cvss_score == 6.4

    def test_no_cvss_when_absent(self) -> None:
        # Plugin 10107 has no CVSS data
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["10107"].cvss_score is None

    def test_cwe_extracted_from_xref(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert by_plugin["42873"].cwe_id == 326

    def test_cve_used_as_raw_ref_when_no_plugin_ref(self) -> None:
        # Plugin 42873 has CVE-2016-2183 → raw_ref should be plugin ID as string
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert "42873" in by_plugin

    def test_ids_prefixed_with_tenable(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        assert all(f.id.startswith("tenable-") for f in findings)

    def test_description_from_plugin(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert "medium strength encryption" in by_plugin["42873"].description

    def test_remediation_from_solution(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "tenable_sample.json")
        by_plugin = {f.raw_ref: f for f in findings}
        assert "Reconfigure" in by_plugin["42873"].remediation
