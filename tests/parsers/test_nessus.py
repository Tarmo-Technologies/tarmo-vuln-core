"""Unit tests for the Nessus ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestNessusIngestor:
    def setup_method(self) -> None:
        self.ingestor = NessusIngestor()

    def test_can_handle_nessus_file(self) -> None:
        nessus_fixture = FIXTURES / "nessus_sample.nessus"
        assert self.ingestor.can_handle(nessus_fixture) is True

    def test_cannot_handle_nmap(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        assert self.ingestor.can_handle(nmap_fixture) is False

    def test_cannot_handle_unknown(self, tmp_path: Path) -> None:
        unknown = tmp_path / "data.txt"
        unknown.write_text("random text")
        assert self.ingestor.can_handle(unknown) is False

    def test_ingest_returns_list(self) -> None:
        nessus_fixture = FIXTURES / "nessus_sample.nessus"
        findings = self.ingestor.ingest(nessus_fixture)
        assert len(findings) == 2  # plugin 42873 + 65821

    def test_ingest_nessus_parses_plugins(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        assert len(findings) == 2  # plugin 42873 + 65821

    def test_can_handle_nonexistent_returns_false(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.nessus") is False

    def test_can_handle_invalid_xml_returns_false(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.nessus"
        bad.write_text("not valid xml <<>>")
        assert self.ingestor.can_handle(bad) is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.nessus")

    def test_ingest_wrong_suffix_raises(self, tmp_path: Path) -> None:
        wrong = tmp_path / "file.xml"
        wrong.write_text("content")
        with pytest.raises(IngestorError, match="Expected .nessus suffix"):
            self.ingestor.ingest(wrong)

    def test_ingest_invalid_xml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.nessus"
        bad.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError, match="Failed to parse .nessus XML"):
            self.ingestor.ingest(bad)

    def test_ingest_finding_ids_follow_naming_convention(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        ids = {f.id for f in findings}
        assert ids == {"nessus-plugin-42873", "nessus-plugin-65821"}

    def test_ingest_finding_source_tool_is_nessus(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        assert all(f.source_tool == "nessus" for f in findings)

    def test_ingest_finding_severity_medium(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_ingest_finding_cvss_score(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        by_id = {f.id: f for f in findings}
        assert by_id["nessus-plugin-42873"].cvss_score == 5.0
        assert by_id["nessus-plugin-65821"].cvss_score == 4.3

    def test_ingest_finding_raw_ref_is_cve(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        by_id = {f.id: f for f in findings}
        assert by_id["nessus-plugin-42873"].raw_ref == "CVE-2016-2183"
        assert by_id["nessus-plugin-65821"].raw_ref == "CVE-2013-2566"

    def test_ingest_finding_affected_hosts(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        assert all("10.0.0.1" in f.affected_hosts for f in findings)

    def test_ingest_finding_title_from_plugin_name(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        by_id = {f.id: f for f in findings}
        assert (
            by_id["nessus-plugin-42873"].title
            == "SSL Medium Strength Cipher Suites Supported (SWEET32)"
        )

    def test_ingest_finding_description_nonempty(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        by_id = {f.id: f for f in findings}
        assert "SSL ciphers that offer medium" in by_id["nessus-plugin-42873"].description
        assert "RC4 in one or more cipher suites" in by_id["nessus-plugin-65821"].description

    def test_ingest_finding_remediation_nonempty(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nessus_sample.nessus")
        by_id = {f.id: f for f in findings}
        # Solution text wraps with newlines (e.g. "medium\nstrength ciphers", "RC4\nciphers")
        assert "avoid use of medium" in by_id["nessus-plugin-42873"].remediation
        assert "avoid use of RC4" in by_id["nessus-plugin-65821"].remediation

    def test_ingest_no_cve_falls_back_to_plugin_id(self, tmp_path: Path) -> None:
        xml = tmp_path / "no_cve.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            '      <ReportItem port="80" svc_name="www" protocol="tcp" severity="2"'
            '                  pluginID="99999" pluginName="Test Finding">'
            "        <description>Test description</description>"
            "        <solution>Test solution</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].raw_ref == "99999"

    # ------------------------------------------------------------------
    # Real-fixture smoke test
    # ------------------------------------------------------------------

    # Source: DanMcInerney/msf-autoshell — real Nessus export (example-scan1.nessus)
    # https://raw.githubusercontent.com/DanMcInerney/msf-autoshell/master/example-scan1.nessus

    def test_ingest_real_nessus_output_structure(self) -> None:
        """Smoke test: real Nessus export from DanMcInerney/msf-autoshell."""
        findings = self.ingestor.ingest(FIXTURES / "nessus_real.nessus")
        assert len(findings) == 12  # 12 unique plugin IDs across all hosts
        assert all(f.source_tool == "nessus" for f in findings)
        ids = {f.id for f in findings}
        assert "nessus-plugin-12218" in ids  # mDNS — appears on 2 hosts → 1 finding
        by_id = {f.id: f for f in findings}
        assert set(by_id["nessus-plugin-12218"].affected_hosts) == {
            "192.168.1.112",
            "192.168.1.111",
        }
        assert by_id["nessus-plugin-25216"].severity == Severity.CRITICAL  # severity="4"

    # ------------------------------------------------------------------
    # Inline-XML edge-case tests
    # ------------------------------------------------------------------

    def test_ingest_missing_host_properties_falls_back_to_name_attr(self, tmp_path: Path) -> None:
        """ReportHost with no HostProperties uses the name attribute as IP."""
        xml = tmp_path / "no_props.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.5">'
            '      <ReportItem port="80" svc_name="www" protocol="tcp" severity="1"'
            '                  pluginID="11111" pluginName="Some Plugin">'
            "        <description>A description</description>"
            "        <solution>A solution</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert "10.0.0.5" in findings[0].affected_hosts

    def test_ingest_multiple_cve_elements_takes_first(self, tmp_path: Path) -> None:
        """ReportItem with two <cve> children: raw_ref uses the first one."""
        xml = tmp_path / "multi_cve.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            '      <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="3"'
            '                  pluginID="42411" pluginName="SMB Share Permissions">'
            "        <description>Share permissions allow unauthenticated access.</description>"
            "        <solution>Restrict share permissions.</solution>"
            "        <cve>CVE-2021-0001</cve>"
            "        <cve>CVE-2021-0002</cve>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].raw_ref == "CVE-2021-0001"

    def test_ingest_missing_cvss_score_is_none(self, tmp_path: Path) -> None:
        """ReportItem without <cvss_base_score>: cvss_score is None."""
        xml = tmp_path / "no_cvss.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            '      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"'
            '                  pluginID="22222" pluginName="SSH Detection">'
            "        <description>SSH is running.</description>"
            "        <solution>N/A</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].cvss_score is None

    def test_ingest_empty_description_falls_back_to_synopsis(self, tmp_path: Path) -> None:
        """Empty <description> falls back to <synopsis> for the finding description."""
        xml = tmp_path / "empty_desc.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            '      <ReportItem port="80" svc_name="www" protocol="tcp" severity="1"'
            '                  pluginID="33333" pluginName="Web Detection">'
            "        <description/>"
            "        <synopsis>Fallback text</synopsis>"
            "        <solution>Some solution</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].description == "Fallback text"

    def test_ingest_grouping_same_plugin_multiple_hosts(self, tmp_path: Path) -> None:
        xml = tmp_path / "multi_host.nessus"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="test">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            '      <ReportItem port="443" svc_name="https" protocol="tcp" severity="2"'
            '                  pluginID="42873"'
            '                  pluginName="SSL Medium Strength Cipher Suites Supported (SWEET32)">'
            "        <description>Test</description>"
            "        <solution>Test</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            '    <ReportHost name="10.0.0.2">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.2</tag>'
            "      </HostProperties>"
            '      <ReportItem port="443" svc_name="https" protocol="tcp" severity="2"'
            '                  pluginID="42873"'
            '                  pluginName="SSL Medium Strength Cipher Suites Supported (SWEET32)">'
            "        <description>Test</description>"
            "        <solution>Test</solution>"
            "      </ReportItem>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert set(findings[0].affected_hosts) == {"10.0.0.1", "10.0.0.2"}

    def test_ingest_invalid_cvss_score_is_none(self, tmp_path: Path) -> None:
        """Non-numeric cvss_base_score must produce cvss_score=None, not crash."""
        xml = tmp_path / "bad_cvss.nessus"
        xml.write_text(
            "<NessusClientData_v2>"
            '  <Report name="r"><ReportHost name="10.0.0.1">'
            '    <ReportItem pluginID="11111" pluginName="Bad CVSS" severity="2">'
            "      <cvss_base_score>N/A</cvss_base_score>"
            "      <description>desc</description><solution>fix</solution>"
            "    </ReportItem>"
            "  </ReportHost></Report>"
            "</NessusClientData_v2>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].cvss_score is None


@pytest.mark.unit
class TestNessusIngestorIngestHosts:
    """Tests for NessusIngestor.ingest_hosts (lines 179-241)."""

    def setup_method(self) -> None:
        self.ingestor = NessusIngestor()

    def test_ingest_hosts_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = self.ingestor.ingest_hosts(tmp_path / "missing.nessus")
        assert result == []

    def test_ingest_hosts_wrong_suffix_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "data.xml"
        f.write_text("<NessusClientData_v2/>")
        result = self.ingestor.ingest_hosts(f)
        assert result == []

    def test_ingest_hosts_invalid_xml_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.nessus"
        f.write_text("<<not xml>>")
        result = self.ingestor.ingest_hosts(f)
        assert result == []

    def test_ingest_hosts_basic_extraction(self, tmp_path: Path) -> None:
        """Full host with ip, hostname, os, mac, and extra properties."""
        f = tmp_path / "hosts.nessus"
        f.write_text(
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="hostname">web.example.com</tag>'
            '        <tag name="operating-system">Linux 5.4</tag>'
            '        <tag name="mac-address">AA:BB:CC:DD:EE:FF</tag>'
            '        <tag name="system-type">general-purpose</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        h = hosts[0]
        assert h.address == "10.0.0.1"
        assert h.hostnames == ["web.example.com"]
        assert h.os == "Linux 5.4"
        assert h.mac == "AA:BB:CC:DD:EE:FF"
        # system-type is not in _SKIP_KEYS, so it should appear in properties
        prop_keys = {p.key for p in h.properties}
        assert "system-type" in prop_keys
        prop_vals = {p.key: p.value for p in h.properties}
        assert prop_vals["system-type"] == "general-purpose"

    def test_ingest_hosts_fallback_to_name_attr_when_no_host_ip(self, tmp_path: Path) -> None:
        """When HostProperties has no host-ip tag, fall back to ReportHost name."""
        f = tmp_path / "fallback.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="192.168.1.50">'
            "      <HostProperties>"
            '        <tag name="hostname">server.local</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].address == "192.168.1.50"
        assert hosts[0].hostnames == ["server.local"]

    def test_ingest_hosts_no_host_properties_falls_back_to_name(self, tmp_path: Path) -> None:
        """ReportHost with no HostProperties element uses the name attribute."""
        f = tmp_path / "no_props.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.9">'
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.9"
        assert hosts[0].hostnames == []
        assert hosts[0].os is None
        assert hosts[0].mac is None
        assert hosts[0].properties == []

    def test_ingest_hosts_skips_host_with_no_ip_and_no_name(self, tmp_path: Path) -> None:
        """ReportHost with empty name and no host-ip tag is skipped."""
        f = tmp_path / "skip.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="">'
            "      <HostProperties>"
            '        <tag name="hostname">orphan.local</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert hosts == []

    def test_ingest_hosts_hostname_equals_ip_excluded(self, tmp_path: Path) -> None:
        """hostname that matches the IP should not appear in hostnames list."""
        f = tmp_path / "hn_eq_ip.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="hostname">10.0.0.1</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].hostnames == []

    def test_ingest_hosts_netbios_name_dedup(self, tmp_path: Path) -> None:
        """netbios-name that duplicates hostname should not appear twice."""
        f = tmp_path / "dedup.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="hostname">box.local</tag>'
            '        <tag name="netbios-name">box.local</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].hostnames == ["box.local"]

    def test_ingest_hosts_netbios_different_from_hostname(self, tmp_path: Path) -> None:
        """netbios-name different from hostname produces two hostnames."""
        f = tmp_path / "two_hn.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="hostname">server.example.com</tag>'
            '        <tag name="netbios-name">SERVER</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].hostnames == ["server.example.com", "SERVER"]

    def test_ingest_hosts_os_fallback_to_os_key(self, tmp_path: Path) -> None:
        """When 'operating-system' is absent, falls back to 'os' key."""
        f = tmp_path / "os_key.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="os">Windows 10</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        assert hosts[0].os == "Windows 10"

    def test_ingest_hosts_skip_keys_not_in_properties(self, tmp_path: Path) -> None:
        """Keys in _SKIP_KEYS must not appear in the properties list."""
        f = tmp_path / "skip_keys.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="hostname">h.local</tag>'
            '        <tag name="netbios-name">H</tag>'
            '        <tag name="operating-system">Linux</tag>'
            '        <tag name="os">Linux</tag>'
            '        <tag name="mac-address">AA:BB:CC:DD:EE:FF</tag>'
            '        <tag name="traceroute-hop-0">10.0.0.254</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        prop_keys = {p.key for p in hosts[0].properties}
        # Only traceroute-hop-0 should survive
        assert prop_keys == {"traceroute-hop-0"}
        assert hosts[0].properties[0].value == "10.0.0.254"

    def test_ingest_hosts_multiple_hosts(self, tmp_path: Path) -> None:
        """Multiple ReportHost elements yield multiple Host objects."""
        f = tmp_path / "multi.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            '    <ReportHost name="10.0.0.2">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.2</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 2
        addresses = {h.address for h in hosts}
        assert addresses == {"10.0.0.1", "10.0.0.2"}

    def test_ingest_hosts_empty_tag_value_excluded_from_properties(self, tmp_path: Path) -> None:
        """Tags with empty text are not added to properties."""
        f = tmp_path / "empty_val.nessus"
        f.write_text(
            "<NessusClientData_v2>"
            '  <Report name="scan">'
            '    <ReportHost name="10.0.0.1">'
            "      <HostProperties>"
            '        <tag name="host-ip">10.0.0.1</tag>'
            '        <tag name="system-type"></tag>'
            '        <tag name="patch-summary">needs update</tag>'
            "      </HostProperties>"
            "    </ReportHost>"
            "  </Report>"
            "</NessusClientData_v2>"
        )
        hosts = self.ingestor.ingest_hosts(f)
        assert len(hosts) == 1
        prop_keys = {p.key for p in hosts[0].properties}
        assert "system-type" not in prop_keys
        assert "patch-summary" in prop_keys

    def test_ingest_hosts_real_fixture(self) -> None:
        """Smoke test: ingest_hosts on real fixture returns expected host count."""
        hosts = self.ingestor.ingest_hosts(FIXTURES / "nessus_real.nessus")
        assert len(hosts) > 0
        addresses = {h.address for h in hosts}
        assert "192.168.1.112" in addresses
        assert "192.168.1.111" in addresses

    def test_cwe_extracted_from_nessus_output(self) -> None:
        """Plugin 10114 has <cwe>200</cwe> — should extract CWE-200."""
        findings = self.ingestor.ingest(FIXTURES / "nessus_real.nessus")
        by_id = {f.id: f for f in findings}
        plugin = by_id.get("nessus-plugin-10114")
        assert plugin is not None
        assert plugin.cwe_id == 200

    def test_cwe_none_when_absent(self) -> None:
        """Plugins without <cwe> should have cwe_id=None."""
        findings = self.ingestor.ingest(FIXTURES / "nessus_real.nessus")
        by_id = {f.id: f for f in findings}
        # Plugin 19506 (Nessus Scan Information) has no CWE
        info = by_id.get("nessus-plugin-19506")
        if info:
            assert info.cwe_id is None
