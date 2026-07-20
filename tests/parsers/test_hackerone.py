"""Unit tests for the HackerOne report import ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.parsers.hackerone import HackerOneIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAMPLE = FIXTURES / "hackerone_sample.json"


@pytest.mark.unit
class TestHackerOneIngestorCanHandle:
    def test_can_handle_sample_fixture(self) -> None:
        assert HackerOneIngestor().can_handle(SAMPLE)

    def test_cannot_handle_bloodhound_json(self) -> None:
        assert not HackerOneIngestor().can_handle(FIXTURES / "bloodhound_sample.json")

    def test_cannot_handle_nonexistent_file(self, tmp_path: Path) -> None:
        assert not HackerOneIngestor().can_handle(tmp_path / "missing.json")

    def test_cannot_handle_random_json(self, tmp_path: Path) -> None:
        p = tmp_path / "other.json"
        p.write_text('{"foo": "bar"}')
        assert not HackerOneIngestor().can_handle(p)

    def test_cannot_handle_tenable_json(self) -> None:
        assert not HackerOneIngestor().can_handle(FIXTURES / "tenable_sample.json")

    def test_cannot_handle_empty_data_array(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text('{"data": []}')
        assert not HackerOneIngestor().can_handle(p)


@pytest.mark.unit
class TestHackerOneIngestorParsing:
    def test_ingest_returns_correct_count(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        assert len(findings) == 3

    def test_sql_injection_finding_title(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        titles = [f.title for f in findings]
        assert any("SQL Injection" in t for t in titles)

    def test_critical_finding_severity(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 1
        assert any("SQL Injection" in f.title for f in critical)

    def test_high_finding_severity(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) == 1
        assert any("XSS" in f.title for f in high)

    def test_medium_finding_severity(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1
        assert any("IDOR" in f.title or "Object Reference" in f.title for f in medium)

    def test_affected_host_populated(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert "api.example.com" in sql.affected_hosts

    def test_source_tool_is_hackerone(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        assert all(f.source_tool == "hackerone" for f in findings)

    def test_cwe_id_populated(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert sql.cwe_id == 89

    def test_cve_in_raw_ref(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert sql.raw_ref == "CVE-2023-44974"

    def test_cvss_score_populated(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert sql.cvss_score == 9.8

    def test_cvss_vector_populated(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert sql.cvss_vector is not None
        assert sql.cvss_vector.startswith("CVSS:3.1")

    def test_id_prefix_is_hackerone(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        assert all(f.id.startswith("hackerone-") for f in findings)

    def test_all_findings_have_description(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        assert all(len(f.description) > 0 for f in findings)

    def test_h1_raw_ref_when_no_cve(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        xss = next(f for f in findings if "XSS" in f.title)
        assert xss.raw_ref is not None
        assert xss.raw_ref.startswith("H1-")

    def test_xss_host_is_www(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        xss = next(f for f in findings if "XSS" in f.title)
        assert "www.example.com" in xss.affected_hosts

    def test_xss_cwe_is_79(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        xss = next(f for f in findings if "XSS" in f.title)
        assert xss.cwe_id == 79

    def test_id_uses_report_id(self) -> None:
        findings = HackerOneIngestor().ingest(SAMPLE)
        sql = next(f for f in findings if "SQL Injection" in f.title)
        assert sql.id == "hackerone-1234567"


@pytest.mark.unit
class TestHackerOneIngestorEdgeCases:
    def test_missing_file_raises_ingestor_error(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.ingestors.base import IngestorError

        with pytest.raises(IngestorError):
            HackerOneIngestor().ingest(tmp_path / "missing.json")

    def test_invalid_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.ingestors.base import IngestorError

        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(IngestorError):
            HackerOneIngestor().ingest(p)

    def test_empty_data_array_returns_no_findings(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text('{"data": []}')
        findings = HackerOneIngestor().ingest(p)
        assert findings == []

    def test_non_report_entries_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "mixed.json"
        p.write_text(
            '{"data": [{"type": "user", "attributes": {"title": "skip me", "state": "open"}}]}'
        )
        findings = HackerOneIngestor().ingest(p)
        assert findings == []

    def test_supported_extensions_includes_json(self) -> None:
        assert ".json" in HackerOneIngestor().supported_extensions

    def test_no_cve_no_host_raw_ref_is_h1_id(self, tmp_path: Path) -> None:
        p = tmp_path / "minimal.json"
        p.write_text(
            '{"data": [{"id": "9999", "type": "report",'
            ' "attributes": {"title": "A Bug", "state": "new",'
            ' "severity_rating": "low", "cve_ids": []}}]}'
        )
        findings = HackerOneIngestor().ingest(p)
        assert len(findings) == 1
        assert findings[0].raw_ref == "H1-9999"
        assert findings[0].severity == Severity.LOW
