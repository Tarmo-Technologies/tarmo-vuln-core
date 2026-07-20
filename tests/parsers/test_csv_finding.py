"""Unit tests for the generic CSV finding ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor
from tarmo_vuln_core.models import Severity

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
SAMPLE_CSV = FIXTURES_DIR / "manual_findings.csv"

_INGESTOR = CsvFindingIngestor()


@pytest.mark.unit
class TestCsvFindingCanHandle:
    def test_accepts_csv_with_required_columns(self) -> None:
        assert _INGESTOR.can_handle(SAMPLE_CSV)

    def test_rejects_xml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "scan.xml"
        f.write_text("<xml/>")
        assert not _INGESTOR.can_handle(f)

    def test_rejects_csv_missing_required_columns(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.csv"
        f.write_text("host,port,name\n192.168.1.1,80,test\n")
        assert not _INGESTOR.can_handle(f)

    def test_rejects_empty_csv(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.csv"
        f.write_text("")
        assert not _INGESTOR.can_handle(f)

    def test_rejects_nonexistent_file(self, tmp_path: Path) -> None:
        assert not _INGESTOR.can_handle(tmp_path / "missing.csv")


@pytest.mark.unit
class TestCsvFindingIngest:
    def test_ingest_sample_returns_four_findings(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        assert len(findings) == 4

    def test_first_finding_id_and_title(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        f = findings[0]
        assert f.id == "ssl-weak-cipher"
        assert f.title == "Weak TLS Cipher Suites Enabled"

    def test_severity_mapping(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-weak-cipher"].severity == Severity.MEDIUM
        assert by_id["sql-injection"].severity == Severity.CRITICAL
        assert by_id["default-creds"].severity == Severity.HIGH
        assert by_id["info-finding"].severity == Severity.INFO

    def test_affected_hosts_parsed_from_csv(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        f = findings[0]
        assert "10.0.0.1" in f.affected_hosts
        assert "10.0.0.2" in f.affected_hosts

    def test_cvss_score_parsed(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-weak-cipher"].cvss_score == pytest.approx(5.9)
        assert by_id["sql-injection"].cvss_score == pytest.approx(9.8)
        assert by_id["default-creds"].cvss_score == pytest.approx(9.1)
        assert by_id["info-finding"].cvss_score is None

    def test_cwe_id_parsed(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-weak-cipher"].cwe_id == 326
        assert by_id["sql-injection"].cwe_id == 89
        assert by_id["default-creds"].cwe_id is None

    def test_compliance_refs_parsed(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        by_id = {f.id: f for f in findings}
        refs = by_id["ssl-weak-cipher"].compliance_refs
        assert "PCI-DSS 6.3.2" in refs
        assert "ISO27001 A.14.1.2" in refs

    def test_steps_parsed(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-weak-cipher"].steps == ["Run sslyze", "Check cipher list"]

    def test_source_tool_is_csv(self) -> None:
        findings = _INGESTOR.ingest(SAMPLE_CSV)
        assert all(f.source_tool == "csv" for f in findings)

    def test_ingest_minimal_csv(self, tmp_path: Path) -> None:
        """A CSV with only required columns should parse without error."""
        f = tmp_path / "minimal.csv"
        f.write_text("title,severity\nSQL Injection,CRITICAL\nXSS,HIGH\n")
        findings = _INGESTOR.ingest(f)
        assert len(findings) == 2
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].description  # default text populated

    def test_ingest_empty_data_returns_empty_list(self, tmp_path: Path) -> None:
        f = tmp_path / "header_only.csv"
        f.write_text("title,severity,affected_hosts\n")
        findings = _INGESTOR.ingest(f)
        assert findings == []

    def test_duplicate_id_gets_disambiguated(self, tmp_path: Path) -> None:
        f = tmp_path / "dup.csv"
        f.write_text("id,title,severity\nfoo,Finding A,HIGH\nfoo,Finding B,MEDIUM\n")
        findings = _INGESTOR.ingest(f)
        ids = [f.id for f in findings]
        assert len(set(ids)) == len(ids)  # all unique

    def test_auto_detected_from_registry(self) -> None:
        from tarmo_vuln_core.ingestors import auto_detect

        ingestor = auto_detect(SAMPLE_CSV)
        assert isinstance(ingestor, CsvFindingIngestor)
