"""Unit tests for the BloodHound attack-path ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.parsers.bloodhound import BloodHoundIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAMPLE = FIXTURES / "bloodhound_sample.json"


@pytest.mark.unit
class TestBloodHoundIngestorCanHandle:
    def test_can_handle_sample_fixture(self) -> None:
        assert BloodHoundIngestor().can_handle(SAMPLE)

    def test_cannot_handle_nmap_xml(self) -> None:
        assert not BloodHoundIngestor().can_handle(FIXTURES / "nmap_sample.xml")

    def test_cannot_handle_nonexistent_file(self, tmp_path: Path) -> None:
        assert not BloodHoundIngestor().can_handle(tmp_path / "missing.json")

    def test_cannot_handle_random_json(self, tmp_path: Path) -> None:
        p = tmp_path / "other.json"
        p.write_text('{"foo": "bar"}')
        assert not BloodHoundIngestor().can_handle(p)

    def test_cannot_handle_tenable_json(self) -> None:
        assert not BloodHoundIngestor().can_handle(FIXTURES / "tenable_sample.json")


@pytest.mark.unit
class TestBloodHoundIngestorParsing:
    def test_ingest_returns_correct_count(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        assert len(findings) == 4

    def test_kerberoastable_finding_title(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        titles = [f.title for f in findings]
        assert any("Kerberoastable" in t for t in titles)

    def test_unconstrained_delegation_is_critical(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 2
        titles = {f.title for f in critical}
        assert any("Unconstrained" in t for t in titles)

    def test_kerberoastable_affected_hosts(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        kerb = next(f for f in findings if "Kerberoastable" in f.title)
        assert "svc_http@CORP.LOCAL" in kerb.affected_hosts
        assert "svc_db@CORP.LOCAL" in kerb.affected_hosts

    def test_source_tool_is_bloodhound(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        assert all(f.source_tool == "bloodhound" for f in findings)

    def test_cwe_id_populated(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        kerb = next(f for f in findings if "Kerberoastable" in f.title)
        assert kerb.cwe_id == 287

    def test_cve_in_raw_ref(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        printnightmare = next(f for f in findings if "PrintNightmare" in f.title)
        assert printnightmare.raw_ref == "CVE-2021-34527"

    def test_all_findings_have_description(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        assert all(len(f.description) > 0 for f in findings)

    def test_all_findings_have_remediation(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        assert all(len(f.remediation) > 0 for f in findings)

    def test_id_prefix_is_bloodhound(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        assert all(f.id.startswith("bloodhound-") for f in findings)

    def test_domain_in_affected_hosts_or_description(self) -> None:
        findings = BloodHoundIngestor().ingest(SAMPLE)
        # Each finding should reference CORP.LOCAL somewhere
        for f in findings:
            assert "CORP.LOCAL" in " ".join(f.affected_hosts) or "CORP.LOCAL" in f.description


@pytest.mark.unit
class TestBloodHoundIngestorEdgeCases:
    def test_missing_file_raises_ingestor_error(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.ingestors.base import IngestorError

        with pytest.raises(IngestorError):
            BloodHoundIngestor().ingest(tmp_path / "missing.json")

    def test_invalid_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.ingestors.base import IngestorError

        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(IngestorError):
            BloodHoundIngestor().ingest(p)

    def test_empty_data_array_returns_no_findings(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text('{"meta": {"version": 1, "type": "bloodhoundfinding"}, "data": []}')
        findings = BloodHoundIngestor().ingest(p)
        assert findings == []

    def test_supported_extensions_includes_json(self) -> None:
        assert ".json" in BloodHoundIngestor().supported_extensions
