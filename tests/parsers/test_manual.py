"""Unit tests for the manual finding ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.manual import ManualIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestManualIngestor:
    def setup_method(self) -> None:
        self.ingestor = ManualIngestor()

    def test_can_handle_yaml(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        assert self.ingestor.can_handle(manual_fixture) is True

    def test_cannot_handle_xml(self) -> None:
        nmap_fixture = FIXTURES / "nmap_sample.xml"
        assert self.ingestor.can_handle(nmap_fixture) is False

    def test_ingest_valid_yaml_returns_finding(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        findings = self.ingestor.ingest(manual_fixture)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_ingest_finding_has_required_fields(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        findings = self.ingestor.ingest(manual_fixture)
        f = findings[0]
        assert f.id
        assert f.title
        assert isinstance(f.severity, Severity)
        assert f.description
        assert f.remediation

    def test_ingest_finding_source_tool_is_manual(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        findings = self.ingestor.ingest(manual_fixture)
        assert findings[0].source_tool == "manual"

    def test_can_handle_nonexistent_returns_false(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.yaml") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.yaml")

    def test_ingest_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("key: [unclosed")
        with pytest.raises(IngestorError, match="Failed to parse YAML"):
            self.ingestor.ingest(bad)

    def test_ingest_non_list_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("key: value\n")
        with pytest.raises(IngestorError, match="Expected a YAML list"):
            self.ingestor.ingest(bad)

    def test_ingest_non_dict_item_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just a string\n")
        with pytest.raises(IngestorError, match="is not a mapping"):
            self.ingestor.ingest(bad)

    def test_ingest_invalid_finding_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("- id: missing-required-fields\n")
        with pytest.raises(IngestorError, match="Invalid finding"):
            self.ingestor.ingest(bad)

    def test_can_handle_yml(self, tmp_path: Path) -> None:
        yml_file = tmp_path / "finding.yml"
        yml_file.write_text("- id: x\n")
        assert self.ingestor.can_handle(yml_file) is True

    def test_can_handle_json(self) -> None:
        json_fixture = FIXTURES / "manual_finding.json"
        assert self.ingestor.can_handle(json_fixture) is True

    def test_ingest_json_format(self) -> None:
        json_fixture = FIXTURES / "manual_finding.json"
        findings = self.ingestor.ingest(json_fixture)
        assert len(findings) == 1
        assert findings[0].id == "sqli-user-search"
        assert findings[0].source_tool == "manual"

    def test_ingest_multiple_findings(self, tmp_path: Path) -> None:
        multi = tmp_path / "multi.yaml"
        multi.write_text(
            "- id: finding-a\n"
            "  title: Finding A\n"
            "  severity: HIGH\n"
            "  description: Description A\n"
            "  impact: Impact A\n"
            "  remediation: Remediation A\n"
            "- id: finding-b\n"
            "  title: Finding B\n"
            "  severity: LOW\n"
            "  description: Description B\n"
            "  impact: Impact B\n"
            "  remediation: Remediation B\n"
        )
        findings = self.ingestor.ingest(multi)
        assert len(findings) == 2

    def test_ingest_source_tool_defaults_to_manual(self) -> None:
        json_fixture = FIXTURES / "manual_finding.json"
        findings = self.ingestor.ingest(json_fixture)
        assert findings[0].source_tool == "manual"

    def test_ingest_affected_hosts_populated(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        findings = self.ingestor.ingest(manual_fixture)
        assert "10.0.0.1" in findings[0].affected_hosts

    def test_ingest_optional_fields_populated(self) -> None:
        manual_fixture = FIXTURES / "manual_finding.yaml"
        findings = self.ingestor.ingest(manual_fixture)
        assert findings[0].cvss_score == 7.4
        assert findings[0].cwe_id == 79
        assert findings[0].owasp_id == "A03:2021"
