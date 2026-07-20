"""Unit tests for the OWASP ZAP XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestZapIngestor:
    def setup_method(self) -> None:
        self.ingestor = ZapIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_zap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "zap_sample.xml") is True

    def test_cannot_handle_nmap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_cannot_handle_invalid_xml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        assert self.ingestor.can_handle(bad) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises_ingestor_error(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_ingest_invalid_xml_raises_ingestor_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError, match="Failed to parse ZAP XML"):
            self.ingestor.ingest(bad)

    # -- Finding correctness tests -----------------------------------------------

    def test_ingest_returns_list(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        assert len(findings) == 3  # pluginids: 10202, 10038, 10015

    def test_source_tool_is_zap(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        assert all(f.source_tool == "zap" for f in findings)

    def test_finding_count(self) -> None:
        # 3 distinct pluginids: 10202, 10038, 10015
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        assert len(findings) == 3

    def test_severity_mapping(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["10202"].severity == Severity.MEDIUM
        assert by_ref["10038"].severity == Severity.LOW
        assert by_ref["10015"].severity == Severity.INFO

    def test_cwe_id_parsed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["10202"].cwe_id == 352

    def test_cwe_id_missing(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["10038"].cwe_id is None

    def test_affected_hosts_merged_across_sites(self) -> None:
        # pluginid 10202 appears in both sites; affected_hosts contains unique hostnames
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        hosts = by_ref["10202"].affected_hosts
        assert len(hosts) == 2
        assert "example.com" in hosts
        assert "api.example.com" in hosts

    def test_instances_parsed_with_host_port_path(self) -> None:
        # pluginid 10202: https://example.com/login -> host=example.com, port=443, path=/login
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        instances = by_ref["10202"].instances
        assert len(instances) == 2
        by_host = {inst.host: inst for inst in instances}
        assert "example.com" in by_host
        assert by_host["example.com"].port == 443
        assert by_host["example.com"].path == "/login"
        assert "api.example.com" in by_host
        assert by_host["api.example.com"].path == "/auth"

    def test_instances_single_site_finding(self) -> None:
        # pluginid 10038 appears only in site example.com with uri https://example.com/
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        instances = by_ref["10038"].instances
        assert len(instances) == 1
        assert instances[0].host == "example.com"
        assert instances[0].port == 443
        assert instances[0].path == "/"

    def test_ids_are_prefixed_with_zap(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        assert all(f.id.startswith("zap-") for f in findings)

    def test_raw_ref_is_pluginid(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert "10202" in by_ref
        assert by_ref["10202"].raw_ref == "10202"

    def test_html_stripped_from_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # pluginid 10202: CDATA has "<br>" stripped; plain text must remain
        csrf_desc = by_ref["10202"].description
        assert "<" not in csrf_desc and ">" not in csrf_desc
        assert "Anti-CSRF tokens" in csrf_desc  # text survives HTML stripping

    def test_html_stripped_from_remediation(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # pluginid 10038: solution has "<br>" stripped; "Content-Security-Policy" text must remain
        csp_rem = by_ref["10038"].remediation
        assert "<" not in csp_rem and ">" not in csp_rem
        assert "Content-Security-Policy" in csp_rem

    # -- smoke test against real fixture -----------------------------------------
    # Source: archerysec/report-sample — real ZAP 2.7.0 scan of demo.testfire.net
    # https://raw.githubusercontent.com/archerysec/report-sample/main/OWASP-ZAP/OWASP-ZAP-v2.7.0.xml

    def test_ingest_real_zap_output_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        # 9 unique pluginids in the fixture
        assert len(findings) == 9

    def test_ingest_real_zap_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        assert all(f.source_tool == "zap" for f in findings)

    def test_ingest_real_zap_ids_prefixed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        assert all(f.id.startswith("zap-") for f in findings)

    def test_ingest_real_zap_xss_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # pluginid 40012 = Cross Site Scripting (Reflected), riskcode 3 = HIGH
        assert "40012" in by_ref
        assert by_ref["40012"].severity == Severity.HIGH
        assert by_ref["40012"].cwe_id == 79

    def test_ingest_real_zap_info_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # pluginid 90030 = WSDL File Passive Scanner, riskcode 0 = INFO
        assert "90030" in by_ref
        assert by_ref["90030"].severity == Severity.INFO

    def test_ingest_real_zap_instances_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # pluginid 10016 has many instances on demo.testfire.net:80
        xss_protect = by_ref["10016"]
        assert len(xss_protect.instances) > 1
        assert all(inst.host == "demo.testfire.net" for inst in xss_protect.instances)
        assert all(inst.port == 80 for inst in xss_protect.instances)
        paths = {inst.path for inst in xss_protect.instances}
        assert "/bank/login.aspx" in paths

    def test_ingest_real_zap_affected_hosts_are_hostnames(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "zap_real.xml")
        # all URIs in the real fixture point to demo.testfire.net
        for f in findings:
            for host in f.affected_hosts:
                assert "http" not in host  # must be hostname, not full URI
