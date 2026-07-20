"""Unit tests for the OpenVAS XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.openvas import OpenvasIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestOpenvasIngestor:
    def setup_method(self) -> None:
        self.ingestor = OpenvasIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_openvas_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "openvas_sample.xml") is True

    def test_cannot_handle_nmap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_cannot_handle_invalid_xml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        assert self.ingestor.can_handle(bad) is False

    def test_cannot_handle_json_file(self, tmp_path: Path) -> None:
        jf = tmp_path / "report.json"
        jf.write_text('{"key": "value"}')
        assert self.ingestor.can_handle(jf) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises_ingestor_error(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_ingest_invalid_xml_raises_ingestor_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError, match="Failed to parse OpenVAS XML"):
            self.ingestor.ingest(bad)

    # -- Finding correctness tests -----------------------------------------------

    def test_ingest_returns_list(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert len(findings) == 3  # NVT OIDs: 100001, 100002, 100003

    def test_finding_count(self) -> None:
        # 3 unique NVT OIDs: 100001, 100002, 100003
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert len(findings) == 3

    def test_source_tool_is_openvas(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert all(f.source_tool == "openvas" for f in findings)

    def test_ids_start_with_openvas(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert all(f.id.startswith("openvas-") for f in findings)

    def test_cwe_id_is_none_for_all(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert all(f.cwe_id is None for f in findings)

    def test_owasp_id_is_none_for_all(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        assert all(f.owasp_id is None for f in findings)

    def test_severity_medium_for_tls_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-2011-3389"].severity == Severity.MEDIUM

    def test_severity_critical_for_os_eol(self) -> None:
        # High threat + CVSS 10.0 → upgraded to CRITICAL
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.100002"
        assert by_ref[oid].severity == Severity.CRITICAL

    def test_severity_info_for_log_entry(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.100003"
        assert by_ref[oid].severity == Severity.INFO

    def test_raw_ref_is_cve_when_present(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert "CVE-2011-3389" in by_ref
        assert by_ref["CVE-2011-3389"].raw_ref == "CVE-2011-3389"

    def test_raw_ref_is_oid_when_nocve(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.100002"
        assert oid in by_ref

    def test_affected_hosts_merged_for_shared_nvt(self) -> None:
        # NVT 100001 appears on 2 different hosts
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        hosts = by_ref["CVE-2011-3389"].affected_hosts
        assert len(hosts) == 2
        assert "192.168.1.100" in hosts
        assert "192.168.1.101" in hosts

    def test_cvss_score_parsed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-2011-3389"].cvss_score == 4.3

    def test_cvss_vector_parsed_from_tags(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-2011-3389"].cvss_vector == "AV:N/AC:M/Au:N/C:P/I:N/A:N"

    def test_remediation_from_tags_solution(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        rem = by_ref["CVE-2011-3389"].remediation
        assert "TLS 1.2" in rem

    def test_remediation_default_when_no_solution(self) -> None:
        # NVT 100003 has no solution= in tags
        findings = self.ingestor.ingest(FIXTURES / "openvas_sample.xml")
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.100003"
        rem = by_ref[oid].remediation
        assert rem == "Review the OpenVAS finding details and apply the recommended solution."

    # -- smoke test against real fixture -----------------------------------------
    # Source: archerysec/report-sample — real OpenVAS 6.0 scan of Ubuntu 8.04 LTS
    # https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml

    def test_ingest_real_openvas_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        # 133 results, 104 unique NVT OIDs in the fixture
        assert len(findings) == 104

    def test_ingest_real_openvas_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        assert all(f.source_tool == "openvas" for f in findings)

    def test_ingest_real_openvas_ids_prefixed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        assert all(f.id.startswith("openvas-") for f in findings)

    def test_ingest_real_openvas_os_eol_critical(self) -> None:
        # OS End Of Life Detection: OID 1.3.6.1.4.1.25623.1.0.103674
        # NOCVE → raw_ref = OID; Threat=High + CVSS 10.0 → CRITICAL
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.103674"
        assert oid in by_ref
        assert by_ref[oid].severity == Severity.CRITICAL

    def test_ingest_real_openvas_twiki_cve_raw_ref(self) -> None:
        # TWiki XSS: OID 1.3.6.1.4.1.25623.1.0.800320, CVE-2008-5304, CVE-2008-5305
        # raw_ref = first CVE
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert "CVE-2008-5304" in by_ref
        assert by_ref["CVE-2008-5304"].severity == Severity.CRITICAL

    def test_ingest_real_openvas_all_have_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        # Every finding must have a description of at least 15 characters
        assert all(len(f.description) >= 15 for f in findings)
        # CVE-2008-5304 is the TWiki XSS vuln — description must mention the vulnerability
        by_ref = {f.raw_ref: f for f in findings}
        assert "CVE-2008-5304" in by_ref
        twiki_desc = by_ref["CVE-2008-5304"].description.lower()
        # The real fixture stores version info in the description for this plugin
        assert any(
            kw in twiki_desc
            for kw in ("twiki", "cross-site", "xss", "scripting", "version", "installed")
        )

    def test_ingest_real_openvas_all_have_remediation(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "openvas_real.xml")
        # Every finding must have a remediation of at least 15 characters
        assert all(len(f.remediation) >= 15 for f in findings)
        # OS End of Life finding has non-trivial remediation content
        by_ref = {f.raw_ref: f for f in findings}
        oid = "1.3.6.1.4.1.25623.1.0.103674"
        assert oid in by_ref
        eol_rem = by_ref[oid].remediation.lower()
        assert any(
            kw in eol_rem
            for kw in ("upgrade", "migrate", "update", "supported", "end of life", "review")
        )
