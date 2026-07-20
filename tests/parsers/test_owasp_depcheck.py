"""Unit tests for the OWASP Dependency-Check JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.owasp_depcheck import OwaspDepcheckIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestOwaspDepcheckIngestor:
    def setup_method(self) -> None:
        self.ingestor = OwaspDepcheckIngestor()

    def test_can_handle_depcheck(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "owasp_depcheck_sample.json") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        assert len(findings) == 3

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        assert all(f.source_tool == "owasp-depcheck" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        assert all(f.id.startswith("depcheck-") for f in findings)

    def test_log4shell_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        log4j = [f for f in findings if "44228" in f.title][0]
        assert log4j.severity == Severity.CRITICAL

    def test_cve_2015_6420_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        cve = [f for f in findings if "2015-6420" in f.title][0]
        assert cve.cwe_id == 502

    def test_affected_hosts(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        log4j = [f for f in findings if "44228" in f.title][0]
        assert "log4j-core-2.14.1.jar" in log4j.affected_hosts

    def test_dedup_by_cve(self) -> None:
        """Each unique CVE should appear only once."""
        findings = self.ingestor.ingest(FIXTURES / "owasp_depcheck_sample.json")
        cve_names = [f.title for f in findings]
        assert len(cve_names) == len(set(cve_names))

    def test_cwe_prefixed_values_are_parsed(self, tmp_path: Path) -> None:
        report = {
            "reportSchema": "https://jeremylong.github.io/DependencyCheck/dependency-check.1.8.xsd",
            "dependencies": [
                {
                    "fileName": "codec.jar",
                    "vulnerabilities": [
                        {
                            "name": "CVE-2024-0001",
                            "severity": "HIGH",
                            "cwes": ["CWE-502"],
                            "description": "prefixed CWE",
                        }
                    ],
                }
            ],
        }
        path = tmp_path / "prefixed.json"
        path.write_text(json.dumps(report), encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 502

    def test_placeholder_cwe_values_are_ignored(self, tmp_path: Path) -> None:
        report = {
            "reportSchema": "https://jeremylong.github.io/DependencyCheck/dependency-check.1.8.xsd",
            "dependencies": [
                {
                    "fileName": "codec.jar",
                    "vulnerabilities": [
                        {
                            "name": "CVE-2024-0002",
                            "severity": "HIGH",
                            "cwes": ["NVD-CWE-noinfo", "CWE-79"],
                            "description": "placeholder first",
                        }
                    ],
                }
            ],
        }
        path = tmp_path / "placeholder.json"
        path.write_text(json.dumps(report), encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 79
