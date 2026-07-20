"""Unit tests for the Metasploit ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.metasploit import MetasploitIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _msf_xml(body: str) -> str:
    """Wrap an XML fragment in a minimal MetasploitV4 root."""
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<MetasploitV4>\n{body}\n</MetasploitV4>'


def _write_xml(tmp_path: Path, body: str) -> Path:
    """Write a MetasploitV4 XML document with the given body to a temp file."""
    path = tmp_path / "test.xml"
    path.write_text(_msf_xml(body))
    return path


@pytest.mark.unit
class TestMetasploitIngestor:
    def setup_method(self) -> None:
        self.ingestor = MetasploitIngestor()

    def test_can_handle_msf_xml(self) -> None:
        msf_fixture = FIXTURES / "metasploit_sample.xml"
        assert self.ingestor.can_handle(msf_fixture) is True

    def test_can_handle_msf_csv(self) -> None:
        csv_fixture = FIXTURES / "metasploit_sample.csv"
        assert self.ingestor.can_handle(csv_fixture) is True

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_cannot_handle_nmap(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        assert self.ingestor.can_handle(nmap_fixture) is False

    def test_cannot_handle_csv_wrong_header(self, tmp_path: Path) -> None:
        bad_csv = tmp_path / "wrong.csv"
        bad_csv.write_text("col1,col2\nval1,val2\n")
        assert self.ingestor.can_handle(bad_csv) is False

    def test_cannot_handle_invalid_xml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        assert self.ingestor.can_handle(bad) is False

    def test_cannot_handle_unknown_suffix(self, tmp_path: Path) -> None:
        unknown = tmp_path / "file.log"
        unknown.write_text("some log output")
        assert self.ingestor.can_handle(unknown) is False

    def test_ingest_xml_returns_list(self) -> None:
        # metasploit_sample.xml has one service (ssh/22/tcp on 10.0.0.1) → 1 finding
        msf_fixture = FIXTURES / "metasploit_sample.xml"
        findings = self.ingestor.ingest(msf_fixture)
        assert len(findings) == 1
        assert findings[0].id == "msf-service-22-tcp-ssh"

    def test_ingest_csv_returns_list(self) -> None:
        # metasploit_sample.csv has 2 rows (SSH and HTTP) → 2 findings
        # (same assertions as test_ingest_csv_content)
        csv_fixture = FIXTURES / "metasploit_sample.csv"
        findings = self.ingestor.ingest(csv_fixture)
        assert len(findings) == 2
        assert all(f.source_tool == "metasploit" for f in findings)

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    # ------------------------------------------------------------------
    # Smoke tests — real fixtures
    # ------------------------------------------------------------------
    # Source: MetasploitV4 host-nested export; original URL no longer available.
    # The file contains authentic MSF artifacts (base64 SMB note, VMware MAC
    # 00:0C:29:63:B3:95, real timestamps) consistent with a 2012 Rapid7 lab export.
    # No current public URL found; file retained as-is for schema coverage.

    def test_ingest_real_xml_structure(self) -> None:
        """Real rapid7 fixture: 1 host-nested service (shell/514/tcp), 0 vulns → 1 finding."""
        real_fixture = FIXTURES / "metasploit_real.xml"
        findings = self.ingestor.ingest(real_fixture)
        # The rapid7 fixture has 1 service (shell on 514/tcp) nested in a host
        assert len(findings) == 1
        assert all(f.source_tool == "metasploit" for f in findings)
        assert all(f.id.startswith("msf-") for f in findings)
        assert all(f.description for f in findings)

    def test_ingest_csv_content(self) -> None:
        """metasploit_sample.csv has 2 rows (SSH and HTTP) → 2 findings."""
        csv_fixture = FIXTURES / "metasploit_sample.csv"
        findings = self.ingestor.ingest(csv_fixture)
        assert len(findings) == 2
        http_finding = next(f for f in findings if "HTTP" in f.title)
        assert http_finding.raw_ref == "CVE-2021-41773"
        assert all(f.source_tool == "metasploit" for f in findings)

    # ------------------------------------------------------------------
    # Edge-case inline XML tests
    # ------------------------------------------------------------------

    def test_ingest_xml_vuln_severity_is_high(self, tmp_path: Path) -> None:
        path = _write_xml(
            tmp_path,
            """
  <vulns>
    <vuln>
      <host>10.0.0.1</host>
      <name>MS17-010 EternalBlue</name>
      <info>Remote code execution via SMB</info>
      <refs><ref>CVE-2017-0143</ref></refs>
    </vuln>
  </vulns>
""",
        )
        findings = self.ingestor.ingest(path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].id.startswith("msf-vuln-")

    def test_ingest_xml_service_severity_is_info(self, tmp_path: Path) -> None:
        path = _write_xml(
            tmp_path,
            """
  <services>
    <service>
      <host>10.0.0.1</host>
      <port>22</port>
      <proto>tcp</proto>
      <name>ssh</name>
      <info>OpenSSH 8.9</info>
    </service>
  </services>
""",
        )
        findings = self.ingestor.ingest(path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].id.startswith("msf-service-")

    def test_ingest_xml_vuln_grouping_multiple_hosts(self, tmp_path: Path) -> None:
        """Two vulns with the same name on different hosts → 1 grouped finding."""
        path = _write_xml(
            tmp_path,
            """
  <vulns>
    <vuln>
      <host>10.0.0.1</host>
      <name>MS17-010</name>
      <info>EternalBlue RCE</info>
    </vuln>
    <vuln>
      <host>10.0.0.2</host>
      <name>MS17-010</name>
      <info>EternalBlue RCE</info>
    </vuln>
  </vulns>
""",
        )
        findings = self.ingestor.ingest(path)
        assert len(findings) == 1
        assert "10.0.0.1" in findings[0].affected_hosts
        assert "10.0.0.2" in findings[0].affected_hosts

    def test_ingest_xml_vuln_raw_ref_from_refs(self, tmp_path: Path) -> None:
        """raw_ref is populated from the first <ref> child of <refs>."""
        path = _write_xml(
            tmp_path,
            """
  <vulns>
    <vuln>
      <host>10.0.0.1</host>
      <name>EternalBlue</name>
      <info>RCE via SMB</info>
      <refs>
        <ref>CVE-2017-0143</ref>
        <ref>MSB-MS17-010</ref>
      </refs>
    </vuln>
  </vulns>
""",
        )
        findings = self.ingestor.ingest(path)
        assert findings[0].raw_ref == "CVE-2017-0143"

    def test_ingest_xml_malformed_raises(self, tmp_path: Path) -> None:
        """Malformed XML raises IngestorError."""
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError):
            self.ingestor.ingest(bad_xml)

    def test_ingest_csv_grouping_same_name_port_multiple_hosts(self, tmp_path: Path) -> None:
        """Two CSV rows with same name+port but different hosts → 1 grouped finding."""
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(
            "host,port,name,info,refs\n10.0.0.1,22,SSH,OpenSSH 8.9,\n10.0.0.2,22,SSH,OpenSSH 9.0,\n"
        )
        findings = self.ingestor.ingest(csv_path)
        assert len(findings) == 1
        assert "10.0.0.1" in findings[0].affected_hosts
        assert "10.0.0.2" in findings[0].affected_hosts
