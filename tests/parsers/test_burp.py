"""Unit tests for the Burp Suite ingestor."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _burp_xml(issues_xml: str) -> str:
    """Wrap issue fragments in a minimal Burp issues root element."""
    return f'<?xml version="1.0"?>\n<issues burpVersion="2.0">\n{issues_xml}\n</issues>'


def _write_burp(tmp_path: Path, issues_xml: str) -> Path:
    p = tmp_path / "burp.xml"
    p.write_text(_burp_xml(issues_xml))
    return p


@pytest.mark.unit
class TestBurpIngestor:
    def setup_method(self) -> None:
        self.ingestor = BurpIngestor()

    # -- existing tests ----------------------------------------------------------

    def test_can_handle_burp_xml(self) -> None:
        burp_fixture = FIXTURES / "burp_sample.xml"
        assert self.ingestor.can_handle(burp_fixture) is True

    def test_cannot_handle_nmap(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        assert self.ingestor.can_handle(nmap_fixture) is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    def test_cannot_handle_invalid_xml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        assert self.ingestor.can_handle(bad) is False

    def test_ingest_returns_list(self) -> None:
        burp_fixture = FIXTURES / "burp_sample.xml"
        findings = self.ingestor.ingest(burp_fixture)
        assert len(findings) == 1
        assert findings[0].title == "SQL injection"

    def test_ingest_sample_populates_instance_path(self) -> None:
        # burp_sample.xml: SQL injection, location="/search [name parameter]"
        findings = self.ingestor.ingest(FIXTURES / "burp_sample.xml")
        assert len(findings[0].instances) == 1
        inst = findings[0].instances[0]
        assert inst.host == "10.0.0.1"
        assert inst.path == "/search [name parameter]"

    def test_ingest_multiple_paths_same_host_create_multiple_instances(
        self, tmp_path: Path
    ) -> None:
        issues = dedent("""\
            <issue>
              <name>XSS</name>
              <host ip="10.0.0.1">http://a.com</host>
              <location>/login [q parameter]</location>
              <severity>High</severity>
            </issue>
            <issue>
              <name>XSS</name>
              <host ip="10.0.0.1">http://a.com</host>
              <location>/search [q parameter]</location>
              <severity>High</severity>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        assert len(findings) == 1
        assert len(findings[0].instances) == 2
        paths = {inst.path for inst in findings[0].instances}
        assert paths == {"/login [q parameter]", "/search [q parameter]"}

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    def test_ingest_invalid_xml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("not valid xml <<>>")
        with pytest.raises(IngestorError, match="Failed to parse Burp XML"):
            self.ingestor.ingest(bad)

    # -- smoke test against real Burp fixture ------------------------------------
    # Source: hvqzao/report-ng — Burp Suite 1.6.05 scan of BodgeIt Store (http://bwa)
    # https://raw.githubusercontent.com/hvqzao/report-ng/master/examples/example-2C-scan-export-Burp.xml

    def test_ingest_real_burp_output_structure(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "burp_real.xml")
        # 7 unique issue names in the fixture
        assert len(findings) == 7
        assert all(f.source_tool == "burp" for f in findings)
        assert all(f.id.startswith("burp-") for f in findings)
        assert all(f.description for f in findings)
        ids = {f.id for f in findings}
        assert "burp-frameable-response-potential-clickjacking" in ids
        by_id = {f.id: f for f in findings}
        assert by_id["burp-frameable-response-potential-clickjacking"].severity == Severity.INFO

    def test_ingest_real_burp_instances_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "burp_real.xml")
        by_id = {f.id: f for f in findings}
        # "Cross-site scripting (reflected)" has one occurrence: /bodgeit/search.jsp [q parameter]
        xss = by_id["burp-cross-site-scripting-reflected"]
        assert len(xss.instances) == 1
        assert xss.instances[0].host == "192.168.187.137"
        assert xss.instances[0].path == "/bodgeit/search.jsp [q parameter]"
        # "Frameable response" has multiple occurrences on different paths
        clickjack = by_id["burp-frameable-response-potential-clickjacking"]
        assert len(clickjack.instances) > 1
        paths = {inst.path for inst in clickjack.instances}
        assert "/bodgeit/" in paths
        assert "/bodgeit/search.jsp" in paths

    # -- edge-case tests ---------------------------------------------------------

    def test_ingest_severity_mapping(self, tmp_path: Path) -> None:
        issues = dedent("""\
            <issue>
              <name>Crit Issue</name>
              <host ip="1.1.1.1">http://a.com</host>
              <severity>Critical</severity>
            </issue>
            <issue>
              <name>High Issue</name>
              <host ip="1.1.1.1">http://a.com</host>
              <severity>High</severity>
            </issue>
            <issue>
              <name>Med Issue</name>
              <host ip="1.1.1.1">http://a.com</host>
              <severity>Medium</severity>
            </issue>
            <issue>
              <name>Low Issue</name>
              <host ip="1.1.1.1">http://a.com</host>
              <severity>Low</severity>
            </issue>
            <issue>
              <name>Info Issue</name>
              <host ip="1.1.1.1">http://a.com</host>
              <severity>Information</severity>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        by_title = {f.title: f for f in findings}
        assert by_title["Crit Issue"].severity == Severity.CRITICAL
        assert by_title["High Issue"].severity == Severity.HIGH
        assert by_title["Med Issue"].severity == Severity.MEDIUM
        assert by_title["Low Issue"].severity == Severity.LOW
        assert by_title["Info Issue"].severity == Severity.INFO

    def test_ingest_grouping_same_name_multiple_hosts(self, tmp_path: Path) -> None:
        issues = dedent("""\
            <issue>
              <name>XSS</name>
              <host ip="10.0.0.1">http://a.com</host>
              <severity>High</severity>
            </issue>
            <issue>
              <name>XSS</name>
              <host ip="10.0.0.2">http://b.com</host>
              <severity>High</severity>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        assert len(findings) == 1
        assert set(findings[0].affected_hosts) == {"10.0.0.1", "10.0.0.2"}

    def test_ingest_remediation_detail_appended(self, tmp_path: Path) -> None:
        issues = dedent("""\
            <issue>
              <name>SQL Injection</name>
              <host ip="10.0.0.1">http://a.com</host>
              <severity>High</severity>
              <remediationBackground>Use parameterized queries.</remediationBackground>
              <remediationDetail>Specifically fix the login endpoint.</remediationDetail>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        assert len(findings) == 1
        remediation = findings[0].remediation
        assert "Use parameterized queries." in remediation
        assert "Specifically fix the login endpoint." in remediation

    def test_ingest_missing_issue_background_falls_back(self, tmp_path: Path) -> None:
        issues = dedent("""\
            <issue>
              <name>Unknown Issue</name>
              <host ip="10.0.0.1">http://a.com</host>
              <severity>Low</severity>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        assert len(findings) == 1
        # When issueBackground is absent, falls back to _BURP_DEFAULT_IMPACT
        assert "Successful exploitation" in findings[0].description

    def test_ingest_id_slug_from_name(self, tmp_path: Path) -> None:
        issues = dedent("""\
            <issue>
              <name>Cross-site scripting (reflected)</name>
              <host ip="10.0.0.1">http://a.com</host>
              <severity>High</severity>
            </issue>
        """)
        p = _write_burp(tmp_path, issues)
        findings = self.ingestor.ingest(p)
        assert len(findings) == 1
        assert findings[0].id == "burp-cross-site-scripting-reflected"
