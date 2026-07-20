"""Unit tests for the Trivy JSON ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.trivy import TrivyIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestTrivyIngestor:
    def setup_method(self) -> None:
        self.ingestor = TrivyIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_trivy_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "trivy_sample.json") is True

    def test_cannot_handle_nmap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_cannot_handle_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        assert self.ingestor.can_handle(bad) is False

    def test_cannot_handle_json_without_results(self, tmp_path: Path) -> None:
        other = tmp_path / "other.json"
        other.write_text('{"data": []}')
        assert self.ingestor.can_handle(other) is False

    def test_cannot_handle_json_results_without_vulnerabilities(self, tmp_path: Path) -> None:
        other = tmp_path / "other.json"
        other.write_text('{"Results": [{"Target": "foo", "Class": "os-pkgs"}]}')
        assert self.ingestor.can_handle(other) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises_ingestor_error(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_ingest_invalid_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        with pytest.raises(IngestorError, match="Failed to parse Trivy JSON"):
            self.ingestor.ingest(bad)

    # -- Finding correctness tests -----------------------------------------------

    def test_ingest_returns_list(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        assert len(findings) == 3  # CVE-SAMPLE-0001, 0002, 0003

    def test_source_tool_is_trivy(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        assert all(f.source_tool == "trivy" for f in findings)

    def test_finding_count(self) -> None:
        # 3 distinct VulnerabilityIDs: CVE-SAMPLE-0001, 0002, 0003
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        assert len(findings) == 3

    def test_severity_mapping(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0001"].severity == Severity.CRITICAL
        assert by_ref["CVE-SAMPLE-0002"].severity == Severity.HIGH
        assert by_ref["CVE-SAMPLE-0003"].severity == Severity.MEDIUM

    def test_cvss_from_nvd(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0001"].cvss_score == 9.5
        expected_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert by_ref["CVE-SAMPLE-0001"].cvss_vector == expected_vector

    def test_cvss_fallback_to_vendor(self) -> None:
        # CVE-SAMPLE-0002 has only redhat CVSS (no nvd) → should fall back to 7.5
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0002"].cvss_score == 7.5

    def test_cvss_none_when_absent(self) -> None:
        # CVE-SAMPLE-0003 has no CVSS data
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0003"].cvss_score is None
        assert by_ref["CVE-SAMPLE-0003"].cvss_vector is None

    def test_cwe_id_parsed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0001"].cwe_id == 79

    def test_cwe_id_missing(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0002"].cwe_id is None
        assert by_ref["CVE-SAMPLE-0003"].cwe_id is None

    def test_deduplication_shared_cve(self) -> None:
        # CVE-SAMPLE-0001 appears in both alpine:3.18 and python:3.11
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        hosts = by_ref["CVE-SAMPLE-0001"].affected_hosts
        assert len(hosts) == 2
        assert "alpine:3.18" in hosts
        assert "python:3.11" in hosts

    def test_ids_are_prefixed_with_trivy(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        assert all(f.id.startswith("trivy-") for f in findings)

    def test_raw_ref_is_cve_id(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert "CVE-SAMPLE-0001" in by_ref
        assert by_ref["CVE-SAMPLE-0001"].raw_ref == "CVE-SAMPLE-0001"

    def test_remediation_with_fixed_version(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["CVE-SAMPLE-0002"].remediation == "Update libssl to version 2.1."
        assert by_ref["CVE-SAMPLE-0003"].remediation == "Update libcurl to version 3.1."

    def test_remediation_default_when_no_fix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        # CVE-SAMPLE-0001 has no FixedVersion
        assert (
            "Update" not in by_ref["CVE-SAMPLE-0001"].remediation
            or "non-vulnerable" in by_ref["CVE-SAMPLE-0001"].remediation
        )

    def test_description_non_empty(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_sample.json")
        by_ref = {f.raw_ref: f for f in findings}
        # CVE-SAMPLE-0001 description is taken directly from the fixture JSON "Description" field
        assert "critical vulnerability in bash" in by_ref["CVE-SAMPLE-0001"].description

    # -- smoke test against real fixture -----------------------------------------
    # Source: aquasecurity/trivy — integration test golden file for debian:buster scan
    # https://raw.githubusercontent.com/aquasecurity/trivy/main/integration/testdata/debian-buster.json.golden

    def test_ingest_real_trivy_output_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_real.json")
        # 2 unique CVEs in debian-buster golden fixture
        assert len(findings) == 2

    def test_ingest_real_trivy_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_real.json")
        assert all(f.source_tool == "trivy" for f in findings)

    def test_ingest_real_trivy_ids_prefixed(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_real.json")
        assert all(f.id.startswith("trivy-") for f in findings)

    def test_ingest_real_trivy_bash_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_real.json")
        by_ref = {f.raw_ref: f for f in findings}
        # CVE-2019-18276: bash priv-drop bug, LOW severity, CWE-273, nvd V3Score=7.8
        assert "CVE-2019-18276" in by_ref
        f = by_ref["CVE-2019-18276"]
        assert f.severity == Severity.LOW
        assert f.cwe_id == 273
        assert f.cvss_score == 7.8

    def test_ingest_real_trivy_libidn2_finding(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trivy_real.json")
        by_ref = {f.raw_ref: f for f in findings}
        # CVE-2019-18224: libidn2 heap overflow, CRITICAL, CWE-787, nvd V3Score=9.8
        assert "CVE-2019-18224" in by_ref
        f = by_ref["CVE-2019-18224"]
        assert f.severity == Severity.CRITICAL
        assert f.cwe_id == 787
        assert f.cvss_score == 9.8
        # has a fixed version → remediation should mention the package
        assert "libidn2-0" in f.remediation
