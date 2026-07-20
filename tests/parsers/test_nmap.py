"""Unit tests for the Nmap ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestNmapIngestor:
    def setup_method(self) -> None:
        self.ingestor = NmapIngestor()

    def test_can_handle_nmap_xml(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        assert self.ingestor.can_handle(nmap_fixture) is True

    def test_cannot_handle_nessus(self) -> None:
        nessus_fixture = FIXTURES / "nessus_sample.nessus"
        assert self.ingestor.can_handle(nessus_fixture) is False

    def test_cannot_handle_unknown(self, tmp_path: Path) -> None:
        unknown = tmp_path / "data.csv"
        unknown.write_text("col1,col2\nval1,val2")
        assert self.ingestor.can_handle(unknown) is False

    def test_ingest_returns_list(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        findings = self.ingestor.ingest(nmap_fixture)
        assert len(findings) == 4  # tcp/22, tcp/80, tcp/443, tcp/23

    def test_ingest_nmap_xml_parses_hosts(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert len(findings) == 4  # tcp/22, tcp/80, tcp/443, tcp/23

    def test_can_handle_nonexistent_returns_false(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_ingest_invalid_xml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError, match="Failed to parse Nmap XML"):
            self.ingestor.ingest(bad)

    def test_ingest_finding_ids_follow_naming_convention(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        ids = {f.id for f in findings}
        assert ids == {
            "nmap-open-tcp-22",
            "nmap-open-tcp-80",
            "nmap-open-tcp-443",
            "nmap-open-tcp-23",
        }

    def test_ingest_finding_source_tool_is_nmap(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert all(f.source_tool == "nmap" for f in findings)

    def test_ingest_finding_severity_is_info(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert all(f.severity == Severity.INFO for f in findings)

    def test_ingest_finding_grouping_by_port(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        port22 = next(f for f in findings if f.id == "nmap-open-tcp-22")
        assert port22.affected_hosts == ["10.0.0.1"]

    def test_ingest_finding_affected_hosts_port_23(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        port23 = next(f for f in findings if f.id == "nmap-open-tcp-23")
        assert port23.affected_hosts == ["10.0.0.2"]

    def test_ingest_finding_has_nonempty_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        port22 = next(f for f in findings if f.id == "nmap-open-tcp-22")
        assert "Port 22/tcp is open and running" in port22.description

    def test_ingest_finding_has_nonempty_impact(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert all("An open port exposes" in f.impact for f in findings)

    def test_ingest_finding_has_nonempty_remediation(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert all("Verify that this service is required" in f.remediation for f in findings)

    def test_ingest_finding_cvss_is_none(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "nmap_sample.xml")
        assert all(f.cvss_score is None for f in findings)

    def test_ingest_empty_host_no_open_ports(self, tmp_path: Path) -> None:
        xml = tmp_path / "empty.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.99" addrtype="ipv4"/>'
            "    <ports/>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert findings == []

    # ------------------------------------------------------------------
    # Real-fixture smoke test
    # ------------------------------------------------------------------

    # Source: mozilla/minion-nmap-plugin — real Nmap 6.40 scan of 192.168.0.0/29
    # https://raw.githubusercontent.com/mozilla/minion-nmap-plugin/master/etc/sample-nmap-output.xml

    def test_ingest_real_nmap_output_structure(self) -> None:
        """Smoke test: real nmap output from Mozilla minion-nmap-plugin."""
        findings = self.ingestor.ingest(FIXTURES / "nmap_real.xml")
        assert len(findings) == 7  # tcp/22,80,88,443,548,3306,8080
        assert all(f.source_tool == "nmap" for f in findings)
        assert all(f.severity == Severity.INFO for f in findings)
        assert all(f.id.startswith("nmap-open-") for f in findings)
        assert all(f.description for f in findings)

    # ------------------------------------------------------------------
    # Inline-XML edge-case tests
    # ------------------------------------------------------------------

    def test_ingest_host_with_mac_address_uses_ipv4(self, tmp_path: Path) -> None:
        """Host with both IPv4 and MAC addresses: only IPv4 should appear."""
        xml = tmp_path / "mac.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            '    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            '        <service name="http"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].affected_hosts == ["10.0.0.1"]
        assert "AA:BB:CC:DD:EE:FF" not in findings[0].affected_hosts

    def test_ingest_udp_port(self, tmp_path: Path) -> None:
        """Open UDP port is parsed and id includes 'udp'."""
        xml = tmp_path / "udp.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.2" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="udp" portid="53">'
            '        <state state="open"/>'
            '        <service name="domain"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].id == "nmap-open-udp-53"

    def test_ingest_port_without_service_element(self, tmp_path: Path) -> None:
        """Open port with no <service> child: finding returned with 'unknown' in title."""
        xml = tmp_path / "no_service.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.3" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="9999">'
            '        <state state="open"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert "unknown" in findings[0].title

    def test_ingest_closed_and_filtered_ports_excluded(self, tmp_path: Path) -> None:
        """Closed and filtered ports are not included; only the open one is."""
        xml = tmp_path / "mixed.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.4" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="22">'
            '        <state state="open"/>'
            '        <service name="ssh"/>'
            "      </port>"
            '      <port protocol="tcp" portid="23">'
            '        <state state="closed"/>'
            "      </port>"
            '      <port protocol="tcp" portid="25">'
            '        <state state="filtered"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].id == "nmap-open-tcp-22"

    def test_ingest_down_host_skipped(self, tmp_path: Path) -> None:
        """Down hosts are skipped; only up hosts contribute findings."""
        xml = tmp_path / "down.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="down"/>'
            '    <address addr="10.0.0.5" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.6" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="443">'
            '        <state state="open"/>'
            '        <service name="https"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].id == "nmap-open-tcp-443"

    # ------------------------------------------------------------------
    # ingest_hosts tests — lines 165-245
    # ------------------------------------------------------------------

    def test_ingest_hosts_from_sample_fixture(self) -> None:
        """ingest_hosts returns Host objects from nmap_sample.xml."""
        hosts = self.ingestor.ingest_hosts(FIXTURES / "nmap_sample.xml")
        assert len(hosts) == 2
        # First host: 10.0.0.1 with hostname, OS, and 3 open ports
        h1 = next(h for h in hosts if h.address == "10.0.0.1")
        assert h1.hostnames == ["host1.example.com"]
        assert h1.os == "Linux 5.x"
        assert h1.os_confidence == 95
        assert h1.mac is None
        assert len(h1.properties) == 3
        port_keys = {p.key for p in h1.properties}
        assert port_keys == {
            "port/22/tcp",
            "port/80/tcp",
            "port/443/tcp",
        }
        # Check service detail includes product+version
        ssh_prop = next(p for p in h1.properties if p.key == "port/22/tcp")
        assert ssh_prop.value == "OpenSSH 8.9"

        # Second host: 10.0.0.2 with no hostnames and no OS
        h2 = next(h for h in hosts if h.address == "10.0.0.2")
        assert h2.hostnames == []
        assert h2.os is None
        assert h2.os_confidence is None
        assert len(h2.properties) == 1
        assert h2.properties[0].key == "port/23/tcp"
        assert h2.properties[0].value == "Linux telnetd"

    def test_ingest_hosts_from_real_fixture(self) -> None:
        """ingest_hosts returns hosts from the real nmap output fixture."""
        hosts = self.ingestor.ingest_hosts(FIXTURES / "nmap_real.xml")
        addresses = {h.address for h in hosts}
        # The real fixture has hosts at 192.168.0.0 through 192.168.0.7
        assert "192.168.0.1" in addresses
        assert "192.168.0.2" in addresses
        h1 = next(h for h in hosts if h.address == "192.168.0.1")
        port_keys = {p.key for p in h1.properties}
        assert "port/22/tcp" in port_keys
        assert "port/88/tcp" in port_keys
        assert "port/548/tcp" in port_keys

    def test_ingest_hosts_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        """ingest_hosts returns empty list for nonexistent file."""
        hosts = self.ingestor.ingest_hosts(tmp_path / "nonexistent.xml")
        assert hosts == []

    def test_ingest_hosts_invalid_xml_returns_empty(self, tmp_path: Path) -> None:
        """ingest_hosts returns empty list for invalid XML."""
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        hosts = self.ingestor.ingest_hosts(bad)
        assert hosts == []

    def test_ingest_hosts_down_host_skipped(self, tmp_path: Path) -> None:
        """Down hosts are excluded from ingest_hosts."""
        xml = tmp_path / "down.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            '  <host><status state="down"/>'
            '    <address addr="10.0.0.5" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert hosts == []

    def test_ingest_hosts_mac_address_extracted(self, tmp_path: Path) -> None:
        """MAC address is extracted into the mac field."""
        xml = tmp_path / "mac.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            '    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="22">'
            '        <state state="open"/>'
            '        <service name="ssh" product="OpenSSH" version="8.9"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.1"
        assert hosts[0].mac == "AA:BB:CC:DD:EE:FF"

    def test_ingest_hosts_os_detection(self, tmp_path: Path) -> None:
        """OS name and accuracy are extracted from osmatch element."""
        xml = tmp_path / "os.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports/>"
            "    <os>"
            '      <osmatch name="Windows 10 build 19041" accuracy="88"/>'
            '      <osmatch name="Windows 10 build 18363" accuracy="85"/>'
            "    </os>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].os == "Windows 10 build 19041"
        assert hosts[0].os_confidence == 88

    def test_ingest_hosts_os_invalid_accuracy(self, tmp_path: Path) -> None:
        """Non-integer accuracy results in os_confidence=None."""
        xml = tmp_path / "os_bad.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports/>"
            "    <os>"
            '      <osmatch name="Linux 5.x" accuracy="high"/>'
            "    </os>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].os == "Linux 5.x"
        assert hosts[0].os_confidence is None

    def test_ingest_hosts_closed_ports_excluded(self, tmp_path: Path) -> None:
        """Only open ports become HostProperty entries."""
        xml = tmp_path / "mixed.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="22">'
            '        <state state="open"/>'
            '        <service name="ssh"/>'
            "      </port>"
            '      <port protocol="tcp" portid="23">'
            '        <state state="closed"/>'
            '        <service name="telnet"/>'
            "      </port>"
            '      <port protocol="tcp" portid="25">'
            '        <state state="filtered"/>'
            '        <service name="smtp"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert len(hosts[0].properties) == 1
        assert hosts[0].properties[0].key == "port/22/tcp"
        assert hosts[0].properties[0].value == "ssh"

    def test_ingest_hosts_no_service_element_fallback(self, tmp_path: Path) -> None:
        """Port with no <service> child uses portid/protocol as value."""
        xml = tmp_path / "no_svc.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="9999">'
            '        <state state="open"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].properties[0].key == "port/9999/tcp"
        assert hosts[0].properties[0].value == "9999/tcp"

    def test_ingest_hosts_multiple_hostnames_deduped(self, tmp_path: Path) -> None:
        """Multiple hostname entries are collected; duplicates removed."""
        xml = tmp_path / "hostnames.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <hostnames>"
            '      <hostname name="web.example.com" type="PTR"/>'
            '      <hostname name="api.example.com" type="user"/>'
            '      <hostname name="web.example.com" type="PTR"/>'
            "    </hostnames>"
            "    <ports/>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].hostnames == ["web.example.com", "api.example.com"]

    def test_ingest_hosts_no_ports_element(self, tmp_path: Path) -> None:
        """Host with no <ports> element has empty properties."""
        xml = tmp_path / "no_ports.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.1"
        assert hosts[0].properties == []

    def test_ingest_hosts_ipv6_address(self, tmp_path: Path) -> None:
        """Host with IPv6 address is parsed correctly."""
        xml = tmp_path / "ipv6.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="::1" addrtype="ipv6"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            '        <service name="http"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "::1"

    def test_ingest_hosts_product_with_version(self, tmp_path: Path) -> None:
        """Service with product and version produces 'product version' detail."""
        xml = tmp_path / "prod_ver.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="3306">'
            '        <state state="open"/>'
            '        <service name="mysql" product="MySQL" version="5.7.42"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].properties[0].value == "MySQL 5.7.42"

    def test_ingest_hosts_product_no_version(self, tmp_path: Path) -> None:
        """Service with product but no version uses just the product."""
        xml = tmp_path / "prod_no_ver.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports>"
            '      <port protocol="tcp" portid="548">'
            '        <state state="open"/>'
            '        <service name="afp" product="netatalk"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].properties[0].value == "netatalk"

    def test_ingest_hosts_os_element_no_osmatch(self, tmp_path: Path) -> None:
        """<os> element with no <osmatch> child: os stays None."""
        xml = tmp_path / "os_empty.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <ports/>"
            "    <os>"
            "    </os>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].os is None
        assert hosts[0].os_confidence is None

    def test_ingest_host_without_status_element(self, tmp_path: Path) -> None:
        """Host with no <status> element should be treated as up (nmap omits it in some outputs)."""
        xml = tmp_path / "no_status.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <hostnames>"
            '      <hostname name="test-host"/>'
            "    </hostnames>"
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            '        <service name="http" product="Apache" version="2.4.41"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        findings = self.ingestor.ingest(xml)
        assert len(findings) == 1
        assert findings[0].id == "nmap-open-tcp-80"
        assert findings[0].affected_hosts == ["10.0.0.1"]
        assert "Apache 2.4.41" in findings[0].description

    def test_ingest_hosts_without_status_element(self, tmp_path: Path) -> None:
        """ingest_hosts with no <status> element should treat host as up."""
        xml = tmp_path / "no_status.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <address addr="10.0.0.1" addrtype="ipv4"/>'
            "    <hostnames>"
            '      <hostname name="test-host"/>'
            "    </hostnames>"
            "    <ports>"
            '      <port protocol="tcp" portid="80">'
            '        <state state="open"/>'
            '        <service name="http" product="Apache" version="2.4.41"/>'
            "      </port>"
            "    </ports>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.1"
        assert hosts[0].hostnames == ["test-host"]
        assert len(hosts[0].properties) == 1
        assert hosts[0].properties[0].key == "port/80/tcp"

    def test_ingest_hosts_host_no_ip_skipped(self, tmp_path: Path) -> None:
        """Host with only MAC address (no IPv4/IPv6) is skipped."""
        xml = tmp_path / "mac_only.xml"
        xml.write_text(
            '<?xml version="1.0"?>'
            "<nmaprun>"
            "  <host>"
            '    <status state="up"/>'
            '    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            "    <ports/>"
            "  </host>"
            "</nmaprun>"
        )
        hosts = self.ingestor.ingest_hosts(xml)
        assert hosts == []
