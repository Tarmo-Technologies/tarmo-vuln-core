"""Structural validation tests for real-world scanner fixture files.

Each test class validates that a fixture:
1. Exists on disk
2. Parses as valid XML / JSON / CSV
3. Has the expected root element or top-level keys
4. Contains at least one pinned count or value
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _parse_xml(path: Path) -> ET.Element:
    tree = ET.parse(path)  # noqa: S314 – trusted test fixtures
    return tree.getroot()


def _count(root: ET.Element, xpath: str) -> int:
    return len(root.findall(xpath))


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestNmapReal:
    path = FIXTURES / "nmap_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "nmaprun"

    def test_host_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//host") == 9


# ---------------------------------------------------------------------------
# Nessus
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestNessusReal:
    path = FIXTURES / "nessus_real.nessus"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "NessusClientData_v2"

    def test_report_host_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//ReportHost") == 4


# ---------------------------------------------------------------------------
# Burp
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestBurpReal:
    path = FIXTURES / "burp_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "issues"

    def test_issue_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//issue") == 16


# ---------------------------------------------------------------------------
# Metasploit
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestMetasploitReal:
    path = FIXTURES / "metasploit_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "MetasploitV4"

    def test_host_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//host") == 1


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestZapReal:
    path = FIXTURES / "zap_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "OWASPZAPReport"

    def test_alertitem_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//alertitem") == 9


# ---------------------------------------------------------------------------
# Acunetix
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestAcunetixReal:
    path = FIXTURES / "acunetix_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "ScanGroup"

    def test_report_item_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//ReportItem") == 4


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestNiktoReal:
    path = FIXTURES / "nikto_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "niktoscan"

    def test_item_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//item") == 13


# ---------------------------------------------------------------------------
# Nexpose
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestNexposeReal:
    path = FIXTURES / "nexpose_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "NexposeReport"

    def test_node_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//node") == 8

    def test_vulnerability_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//vulnerability") == 136


# ---------------------------------------------------------------------------
# OpenVAS
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestOpenvasReal:
    path = FIXTURES / "openvas_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "report"

    def test_result_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//result") == 151


# ---------------------------------------------------------------------------
# Qualys
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestQualysReal:
    path = FIXTURES / "qualys_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "ASSET_DATA_REPORT"

    def test_host_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//HOST") == 7

    def test_vuln_details_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//VULN_DETAILS") == 93


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestSarifReal:
    path = FIXTURES / "sarif_real.json"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert "version" in data
        assert "runs" in data

    def test_sarif_version(self) -> None:
        data = json.loads(self.path.read_text())
        assert data["version"] == "2.1.0"

    def test_result_count(self) -> None:
        data = json.loads(self.path.read_text())
        results = data["runs"][0]["results"]
        assert len(results) == 1


# ---------------------------------------------------------------------------
# SSLyze
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestSslyzeReal:
    path = FIXTURES / "sslyze_real.json"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert "server_scan_results" in data
        assert "sslyze_version" in data

    def test_has_scan_results(self) -> None:
        data = json.loads(self.path.read_text())
        assert len(data["server_scan_results"]) >= 1


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestTrivyReal:
    path = FIXTURES / "trivy_real.json"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert "Results" in data
        assert "ArtifactName" in data

    def test_vulnerability_count(self) -> None:
        data = json.loads(self.path.read_text())
        total = sum(len(r.get("Vulnerabilities", [])) for r in data["Results"])
        assert total == 2


# ---------------------------------------------------------------------------
# WPScan
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestWpscanReal:
    path = FIXTURES / "wpscan_real.json"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert "banner" in data
        assert "target_url" in data

    def test_has_version_info(self) -> None:
        data = json.loads(self.path.read_text())
        assert "version" in data


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestBanditReal:
    path = FIXTURES / "bandit_real.json"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert "errors" in data
        assert "generated_at" in data
        assert "metrics" in data
        assert "results" in data

    def test_result_count(self) -> None:
        data = json.loads(self.path.read_text())
        assert len(data["results"]) == 35

    def test_first_test_id(self) -> None:
        data = json.loads(self.path.read_text())
        assert data["results"][0]["test_id"] == "B322"


# ---------------------------------------------------------------------------
# Semgrep (SARIF)
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestSemgrepReal:
    path = FIXTURES / "semgrep_real.sarif"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_json(self) -> None:
        data = json.loads(self.path.read_text())
        assert data["version"] == "2.1.0"
        assert "runs" in data

    def test_result_count(self) -> None:
        data = json.loads(self.path.read_text())
        assert len(data["runs"][0]["results"]) == 6

    def test_tool_name(self) -> None:
        data = json.loads(self.path.read_text())
        assert data["runs"][0]["tool"]["driver"]["name"] == "semgrep"


# ---------------------------------------------------------------------------
# Cppcheck
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestCppcheckReal:
    path = FIXTURES / "cppcheck_real.xml"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_xml(self) -> None:
        root = _parse_xml(self.path)
        assert root.tag == "results"

    def test_version(self) -> None:
        root = _parse_xml(self.path)
        assert root.attrib["version"] == "2"

    def test_error_count(self) -> None:
        root = _parse_xml(self.path)
        assert _count(root, ".//error") == 13

    def test_first_error_id(self) -> None:
        root = _parse_xml(self.path)
        first_error = root.findall(".//error")[0]
        assert first_error.attrib["id"] == "unusedVariable"


# ---------------------------------------------------------------------------
# Flawfinder
# ---------------------------------------------------------------------------


@pytest.mark.real_fixture
class TestFlawfinderReal:
    path = FIXTURES / "flawfinder_real.csv"

    def test_file_exists(self) -> None:
        assert self.path.exists()

    def test_parses_as_csv(self) -> None:
        with self.path.open(newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
            assert "File" in header
            assert "Line" in header
            assert "Column" in header

    def test_row_count(self) -> None:
        with self.path.open(newline="") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            rows = list(reader)
            assert len(rows) == 39

    def test_cwe_120_present(self) -> None:
        content = self.path.read_text()
        assert "CWE-120" in content
