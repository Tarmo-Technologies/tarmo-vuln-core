"""Tests that fixture files exist and are parseable."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from defusedxml.ElementTree import parse as safe_parse

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestNmapFixture:
    def test_file_exists(self) -> None:
        assert (FIXTURES_DIR / "nmap_sample.xml").is_file()

    def test_xml_root_tag(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "nmap_sample.xml")
        assert tree.getroot().tag == "nmaprun"

    def test_has_hosts(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "nmap_sample.xml")
        hosts = tree.getroot().findall("host")
        assert len(hosts) == 2


class TestNessusFixture:
    def test_file_exists(self) -> None:
        assert (FIXTURES_DIR / "nessus_sample.nessus").is_file()

    def test_xml_root_tag(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "nessus_sample.nessus")
        assert tree.getroot().tag == "NessusClientData_v2"

    def test_has_report_items(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "nessus_sample.nessus")
        items = tree.getroot().findall(".//ReportItem")
        assert len(items) == 2


class TestBurpFixture:
    def test_file_exists(self) -> None:
        assert (FIXTURES_DIR / "burp_sample.xml").is_file()

    def test_xml_root_tag(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "burp_sample.xml")
        assert tree.getroot().tag == "issues"

    def test_has_issues(self) -> None:
        tree = safe_parse(FIXTURES_DIR / "burp_sample.xml")
        issues = tree.getroot().findall("issue")
        assert len(issues) == 1


class TestManualJsonFixture:
    def test_file_exists(self) -> None:
        assert (FIXTURES_DIR / "manual_finding.json").is_file()

    def test_valid_json(self) -> None:
        data = json.loads((FIXTURES_DIR / "manual_finding.json").read_text())
        assert isinstance(data, list)
        assert len(data) == 1

    def test_first_finding_has_required_fields(self) -> None:
        data = json.loads((FIXTURES_DIR / "manual_finding.json").read_text())
        finding = data[0]
        assert finding["id"] == "sqli-user-search"
        assert finding["severity"] == "HIGH"


class TestManualYamlFixture:
    def test_file_exists(self) -> None:
        assert (FIXTURES_DIR / "manual_finding.yaml").is_file()

    def test_valid_yaml(self) -> None:
        data = yaml.safe_load((FIXTURES_DIR / "manual_finding.yaml").read_text())
        assert isinstance(data, list)
        assert len(data) == 1

    def test_first_finding_has_required_fields(self) -> None:
        data = yaml.safe_load((FIXTURES_DIR / "manual_finding.yaml").read_text())
        finding = data[0]
        assert finding["id"] == "reflected-xss-login"
        assert finding["severity"] == "HIGH"
