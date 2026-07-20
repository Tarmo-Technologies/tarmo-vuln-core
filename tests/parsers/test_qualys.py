"""Tests for the Qualys ASSET_DATA_REPORT XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.parsers.qualys import QualysIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture()
def ingestor() -> QualysIngestor:
    return QualysIngestor()


@pytest.fixture()
def real_fixture() -> Path:
    return FIXTURES / "qualys_real.xml"


@pytest.fixture()
def sample_fixture(tmp_path: Path) -> Path:
    """Minimal Qualys ASSET_DATA_REPORT with 2 hosts and 2 QIDs."""
    xml = """\
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ASSET_DATA_REPORT SYSTEM "https://qualysguard.qualys.com/asset_data_report.dtd">
<ASSET_DATA_REPORT>
  <HEADER>
    <RISK_SCORE_SUMMARY><TOTAL_VULNERABILITIES>2</TOTAL_VULNERABILITIES></RISK_SCORE_SUMMARY>
  </HEADER>
  <HOST_LIST>
    <HOST>
      <IP>10.0.0.1</IP>
      <DNS><![CDATA[host-a.example.com]]></DNS>
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID id="qid_38628">38628</QID>
          <TYPE>Vuln</TYPE>
          <PORT>443</PORT>
          <VULN_STATUS>Active</VULN_STATUS>
          <CVSS_FINAL>4.3</CVSS_FINAL>
        </VULN_INFO>
        <VULN_INFO>
          <QID id="qid_42410">42410</QID>
          <TYPE>Vuln</TYPE>
          <VULN_STATUS>Active</VULN_STATUS>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </HOST>
    <HOST>
      <IP>10.0.0.2</IP>
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID id="qid_38628">38628</QID>
          <TYPE>Vuln</TYPE>
          <PORT>80</PORT>
          <VULN_STATUS>Active</VULN_STATUS>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </HOST>
  </HOST_LIST>
  <GLOSSARY>
    <VULN_DETAILS_LIST>
      <VULN_DETAILS id="qid_38628">
        <QID id="qid_38628">38628</QID>
        <TITLE><![CDATA[SSL/TLS Use of Weak RC4 Cipher]]></TITLE>
        <SEVERITY>3</SEVERITY>
        <THREAT><![CDATA[RC4 cipher is broken and deprecated.]]></THREAT>
        <IMPACT><![CDATA[Traffic may be decrypted.]]></IMPACT>
        <SOLUTION><![CDATA[Disable RC4 cipher suites.]]></SOLUTION>
        <CVE_ID_LIST>
          <CVE_ID><ID>CVE-2013-2566</ID></CVE_ID>
        </CVE_ID_LIST>
        <CVSS_SCORE><CVSS_BASE source="service">4.3</CVSS_BASE></CVSS_SCORE>
        <CVSS3_SCORE><CVSS3_BASE>-</CVSS3_BASE></CVSS3_SCORE>
      </VULN_DETAILS>
      <VULN_DETAILS id="qid_42410">
        <QID id="qid_42410">42410</QID>
        <TITLE><![CDATA[SSL Certificate Signed with Weak Hashing Algorithm]]></TITLE>
        <SEVERITY>4</SEVERITY>
        <THREAT><![CDATA[Certificate uses SHA-1.]]></THREAT>
        <IMPACT><![CDATA[Certificate forgery possible.]]></IMPACT>
        <SOLUTION><![CDATA[Reissue certificate with SHA-256.]]></SOLUTION>
        <CVSS_SCORE><CVSS_BASE source="service">5.0</CVSS_BASE></CVSS_SCORE>
        <CVSS3_SCORE><CVSS3_BASE>-</CVSS3_BASE></CVSS3_SCORE>
      </VULN_DETAILS>
    </VULN_DETAILS_LIST>
  </GLOSSARY>
</ASSET_DATA_REPORT>"""
    p = tmp_path / "qualys_sample.xml"
    p.write_text(xml)
    return p


@pytest.mark.unit
class TestQualysCanHandle:
    def test_accepts_qualys_xml(self, ingestor: QualysIngestor, real_fixture: Path) -> None:
        assert ingestor.can_handle(real_fixture) is True

    def test_accepts_sample_fixture(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        assert ingestor.can_handle(sample_fixture) is True

    def test_rejects_nmap_xml(self, ingestor: QualysIngestor, tmp_path: Path) -> None:
        p = tmp_path / "nmap.xml"
        p.write_text("<nmaprun/>")
        assert ingestor.can_handle(p) is False

    def test_rejects_json(self, ingestor: QualysIngestor, tmp_path: Path) -> None:
        p = tmp_path / "scan.json"
        p.write_text("{}")
        assert ingestor.can_handle(p) is False

    def test_rejects_missing_file(self, ingestor: QualysIngestor, tmp_path: Path) -> None:
        p = tmp_path / "missing.xml"
        assert ingestor.can_handle(p) is False


@pytest.mark.unit
class TestQualysIngestSample:
    def test_finding_count(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        assert len(findings) == 2

    def test_qid_38628_present(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert "ssl-tls-use-of-weak-rc4-cipher" in by_id

    def test_severity_medium_for_qid_38628(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-tls-use-of-weak-rc4-cipher"].severity == Severity.MEDIUM

    def test_severity_high_for_qid_42410(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        rc4 = next(f for f in findings if "weak-hashing" in f.id or "sha" in f.id.lower())
        assert rc4.severity == Severity.HIGH

    def test_merged_hosts_for_qid_38628(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        """QID 38628 appears on both 10.0.0.1:443 and 10.0.0.2:80 — should be merged."""
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        rc4 = by_id["ssl-tls-use-of-weak-rc4-cipher"]
        assert len(rc4.affected_hosts) == 2
        hosts_str = " ".join(rc4.affected_hosts)
        assert "10.0.0.1" in hosts_str
        assert "10.0.0.2" in hosts_str

    def test_host_includes_port(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        """Host string for port-qualified VULN_INFO should include :PORT."""
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        rc4 = by_id["ssl-tls-use-of-weak-rc4-cipher"]
        assert any(":443" in h for h in rc4.affected_hosts)

    def test_dns_included_in_host_string(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        rc4 = by_id["ssl-tls-use-of-weak-rc4-cipher"]
        assert any("host-a.example.com" in h for h in rc4.affected_hosts)

    def test_cve_as_raw_ref(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-tls-use-of-weak-rc4-cipher"].raw_ref == "CVE-2013-2566"

    def test_no_cve_uses_qid_raw_ref(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        # QID 42410 has no CVE — raw_ref should be QID:42410
        no_cve = next(f for f in findings if f.raw_ref and f.raw_ref.startswith("QID:"))
        assert no_cve.raw_ref == "QID:42410"

    def test_source_tool_is_qualys(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        assert all(f.source_tool == "qualys" for f in findings)

    def test_description_from_glossary(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert "RC4" in by_id["ssl-tls-use-of-weak-rc4-cipher"].description

    def test_remediation_from_glossary(
        self, ingestor: QualysIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert "RC4" in by_id["ssl-tls-use-of-weak-rc4-cipher"].remediation

    def test_cvss_score_from_glossary(self, ingestor: QualysIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-tls-use-of-weak-rc4-cipher"].cvss_score == 4.3

    def test_empty_host_list_returns_empty(self, ingestor: QualysIngestor, tmp_path: Path) -> None:
        xml = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            "<ASSET_DATA_REPORT><HEADER/></ASSET_DATA_REPORT>"
        )
        p = tmp_path / "empty.xml"
        p.write_text(xml)
        findings = ingestor.ingest(p)
        assert findings == []


@pytest.mark.unit
class TestQualysIngestReal:
    # Source: dradis/dradis-qualys — real Qualys ASSET_DATA_REPORT fixture from
    # the dradis-qualys integration project
    # https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/unittests/scans/qualys/Qualys_Sample_Report.xml
    def test_real_fixture_finding_count(self, ingestor: QualysIngestor, real_fixture: Path) -> None:
        """Real fixture has 92 unique QIDs across 7 hosts."""
        findings = ingestor.ingest(real_fixture)
        assert len(findings) == 92

    def test_real_fixture_critical_shellshock(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) == 5

    def test_real_fixture_shellshock_raw_ref(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        refs = {f.raw_ref for f in findings}
        assert "CVE-2014-6271" in refs

    def test_real_fixture_dns_host_name_info(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        """QID 6 (DNS Host Name) should be INFO severity."""
        findings = ingestor.ingest(real_fixture)
        dns_finding = next(f for f in findings if f.raw_ref == "QID:6")
        assert dns_finding.severity == Severity.INFO
        assert dns_finding.title == "DNS Host Name"

    def test_real_fixture_qid6_hosts_include_demo13(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        dns_finding = next(f for f in findings if f.raw_ref == "QID:6")
        assert any("64.41.200.243" in h for h in dns_finding.affected_hosts)

    def test_real_fixture_all_have_source_tool(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        assert all(f.source_tool == "qualys" for f in findings)

    def test_real_fixture_severity_distribution(
        self, ingestor: QualysIngestor, real_fixture: Path
    ) -> None:
        from collections import Counter

        findings = ingestor.ingest(real_fixture)
        dist = Counter(f.severity.value for f in findings)
        assert dist["CRITICAL"] == 5
        assert dist["HIGH"] == 3
        assert dist["INFO"] == 46
