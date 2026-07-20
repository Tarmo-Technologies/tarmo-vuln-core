"""Tests for the SSLyze JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.parsers.sslyze import SslyzeIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture()
def ingestor() -> SslyzeIngestor:
    return SslyzeIngestor()


@pytest.fixture()
def real_fixture() -> Path:
    return FIXTURES / "sslyze_real.json"


@pytest.fixture()
def sample_fixture(tmp_path: Path) -> Path:
    """Minimal SSLyze JSON with one server that has TLS 1.0, heartbleed, and ROBOT."""
    data = {
        "server_scan_results": [
            {
                "scan_status": "COMPLETED",
                "server_location": {"hostname": "example.com", "port": 443},
                "scan_result": {
                    "tls_1_0_cipher_suites": {
                        "status": "COMPLETED",
                        "result": {"is_tls_version_supported": True},
                    },
                    "tls_1_1_cipher_suites": {
                        "status": "COMPLETED",
                        "result": {"is_tls_version_supported": False},
                    },
                    "ssl_2_0_cipher_suites": {
                        "status": "COMPLETED",
                        "result": {"is_tls_version_supported": True},
                    },
                    "ssl_3_0_cipher_suites": {
                        "status": "COMPLETED",
                        "result": {"is_tls_version_supported": False},
                    },
                    "heartbleed": {
                        "status": "COMPLETED",
                        "result": {"is_vulnerable_to_heartbleed": True},
                    },
                    "openssl_ccs_injection": {
                        "status": "COMPLETED",
                        "result": {"is_vulnerable_to_ccs_injection": False},
                    },
                    "robot": {
                        "status": "COMPLETED",
                        "result": {"robot_result": "VULNERABLE_STRONG_ORACLE"},
                    },
                    "tls_compression": {
                        "status": "COMPLETED",
                        "result": {"supports_compression": True},
                    },
                    "session_renegotiation": {
                        "status": "COMPLETED",
                        "result": {"is_vulnerable_to_client_renegotiation_dos": False},
                    },
                },
            },
        ]
    }
    p = tmp_path / "sslyze_sample.json"
    p.write_text(json.dumps(data))
    return p


@pytest.mark.unit
class TestSslyzeCanHandle:
    def test_accepts_sslyze_json(self, ingestor: SslyzeIngestor, real_fixture: Path) -> None:
        assert ingestor.can_handle(real_fixture) is True

    def test_rejects_non_json(self, ingestor: SslyzeIngestor, tmp_path: Path) -> None:
        p = tmp_path / "scan.xml"
        p.write_text("<root/>")
        assert ingestor.can_handle(p) is False

    def test_rejects_json_without_key(self, ingestor: SslyzeIngestor, tmp_path: Path) -> None:
        p = tmp_path / "other.json"
        p.write_text(json.dumps({"Results": []}))
        assert ingestor.can_handle(p) is False

    def test_rejects_empty_json(self, ingestor: SslyzeIngestor, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.write_text("{}")
        assert ingestor.can_handle(p) is False

    def test_rejects_missing_file(self, ingestor: SslyzeIngestor, tmp_path: Path) -> None:
        p = tmp_path / "missing.json"
        assert ingestor.can_handle(p) is False


@pytest.mark.unit
class TestSslyzeIngestSample:
    def test_tls10_detected(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "tls-1-0-enabled" in ids

    def test_ssl20_detected(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "ssl-v2-enabled" in ids

    def test_ssl20_severity_critical(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["ssl-v2-enabled"].severity == Severity.CRITICAL

    def test_tls10_severity_medium(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["tls-1-0-enabled"].severity == Severity.MEDIUM

    def test_heartbleed_detected(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "openssl-heartbleed" in ids

    def test_heartbleed_severity_critical(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["openssl-heartbleed"].severity == Severity.CRITICAL

    def test_robot_detected(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "tls-robot-attack" in ids

    def test_crime_compression_detected(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "tls-crime-compression" in ids

    def test_tls11_not_detected_when_not_supported(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "tls-1-1-enabled" not in ids

    def test_ssl30_not_detected_when_not_supported(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "ssl-v3-enabled" not in ids

    def test_ccs_not_detected_when_not_vulnerable(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "openssl-ccs-injection" not in ids

    def test_renegotiation_not_detected_when_not_vulnerable(
        self, ingestor: SslyzeIngestor, sample_fixture: Path
    ) -> None:
        findings = ingestor.ingest(sample_fixture)
        ids = {f.id for f in findings}
        assert "tls-renegotiation-dos" not in ids

    def test_host_in_affected_hosts(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        by_id = {f.id: f for f in findings}
        assert "example.com:443" in by_id["tls-1-0-enabled"].affected_hosts

    def test_source_tool_is_sslyze(self, ingestor: SslyzeIngestor, sample_fixture: Path) -> None:
        findings = ingestor.ingest(sample_fixture)
        assert all(f.source_tool == "sslyze" for f in findings)

    def test_skips_error_no_connectivity(self, ingestor: SslyzeIngestor, tmp_path: Path) -> None:
        data = {
            "server_scan_results": [
                {
                    "scan_status": "ERROR_NO_CONNECTIVITY",
                    "server_location": {"hostname": "unreachable.example.com", "port": 443},
                }
            ]
        }
        p = tmp_path / "no_conn.json"
        p.write_text(json.dumps(data))
        findings = ingestor.ingest(p)
        assert findings == []


@pytest.mark.unit
class TestSslyzeIngestReal:
    # Source: nabla-c0d3/sslyze — real SSLyze output JSON from the project's own test suite
    # https://raw.githubusercontent.com/nabla-c0d3/sslyze/release/tests/json_tests/sslyze_output.json
    def test_real_fixture_finding_count(self, ingestor: SslyzeIngestor, real_fixture: Path) -> None:
        """Real fixture has 2 completed servers, both with TLS 1.0 + TLS 1.1 enabled
        and both vulnerable to ROBOT — 3 findings total."""
        findings = ingestor.ingest(real_fixture)
        assert len(findings) == 3

    def test_real_fixture_finding_ids(self, ingestor: SslyzeIngestor, real_fixture: Path) -> None:
        findings = ingestor.ingest(real_fixture)
        ids = {f.id for f in findings}
        assert "tls-1-0-enabled" in ids
        assert "tls-1-1-enabled" in ids
        assert "tls-robot-attack" in ids

    def test_real_fixture_facebook_host_in_tls10(
        self, ingestor: SslyzeIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        by_id = {f.id: f for f in findings}
        assert "www.facebook.com:443" in by_id["tls-1-0-enabled"].affected_hosts

    def test_real_fixture_google_host_in_tls11(
        self, ingestor: SslyzeIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        by_id = {f.id: f for f in findings}
        assert "www.google.com:443" in by_id["tls-1-1-enabled"].affected_hosts

    def test_real_fixture_both_hosts_in_tls10(
        self, ingestor: SslyzeIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        by_id = {f.id: f for f in findings}
        hosts = by_id["tls-1-0-enabled"].affected_hosts
        assert "www.facebook.com:443" in hosts
        assert "www.google.com:443" in hosts

    def test_real_fixture_no_heartbleed(self, ingestor: SslyzeIngestor, real_fixture: Path) -> None:
        findings = ingestor.ingest(real_fixture)
        ids = {f.id for f in findings}
        assert "openssl-heartbleed" not in ids

    def test_real_fixture_severity_medium_for_tls10(
        self, ingestor: SslyzeIngestor, real_fixture: Path
    ) -> None:
        findings = ingestor.ingest(real_fixture)
        by_id = {f.id: f for f in findings}
        assert by_id["tls-1-0-enabled"].severity == Severity.MEDIUM
