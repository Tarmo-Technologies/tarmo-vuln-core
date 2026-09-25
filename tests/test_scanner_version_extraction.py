"""Tests for extract_scanner_version on BaseIngestor and its subclasses."""

from __future__ import annotations

import json
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor
from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor
from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.ingestors.parsers.semgrep import SemgrepIngestor
from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor
from tarmo_vuln_core.models import Finding


def test_base_default_returns_none() -> None:
    class Dummy(BaseIngestor):
        def can_handle(self, path: Path) -> bool:
            return False

        def ingest(self, path: Path) -> list[Finding]:
            return []

    assert Dummy().extract_scanner_version(b"anything") is None


def test_semgrep_pulls_version_from_sarif(tmp_path: Path) -> None:
    """SemgrepIngestor is SARIF-based; version lives in runs[0].tool.driver.version."""
    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "version": "1.51.0", "rules": []}},
                "results": [],
            }
        ],
    }
    raw = json.dumps(sarif).encode()
    ing = SemgrepIngestor()
    assert ing.extract_scanner_version(raw) == "1.51.0"


def test_semgrep_pulls_semantic_version_from_real_driver() -> None:
    """Semgrep 1.160 writes driver.semanticVersion (no driver.version) and names
    itself 'Semgrep OSS'."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "Semgrep OSS", "semanticVersion": "1.160.0", "rules": []}
                },
                "results": [],
            }
        ],
    }
    assert SemgrepIngestor().extract_scanner_version(json.dumps(sarif).encode()) == "1.160.0"


def test_semgrep_real_fixture_version() -> None:
    raw = (Path(__file__).parent / "fixtures" / "semgrep_real.sarif").read_bytes()
    assert SemgrepIngestor().extract_scanner_version(raw) == "1.54.1"


def test_semgrep_missing_version_returns_none() -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "results": [],
            }
        ],
    }
    ing = SemgrepIngestor()
    assert ing.extract_scanner_version(json.dumps(sarif).encode()) is None


def test_semgrep_malformed_json_returns_none() -> None:
    ing = SemgrepIngestor()
    assert ing.extract_scanner_version(b"not json") is None


def test_checkmarx_pulls_version_from_xml(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "checkmarx_sample.xml"
    raw = fixture.read_bytes()
    ing = CheckmarxIngestor()
    version = ing.extract_scanner_version(raw)
    assert version == "9.0"


def test_checkmarx_missing_version_returns_none() -> None:
    xml_bytes = b'<?xml version="1.0"?><CxXMLResults></CxXMLResults>'
    ing = CheckmarxIngestor()
    assert ing.extract_scanner_version(xml_bytes) is None


def test_checkmarx_malformed_xml_returns_none() -> None:
    ing = CheckmarxIngestor()
    assert ing.extract_scanner_version(b"<broken") is None


def test_zap_pulls_version_from_xml(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "zap_sample.xml"
    raw = fixture.read_bytes()
    ing = ZapIngestor()
    version = ing.extract_scanner_version(raw)
    assert version == "2.12.0"


def test_zap_missing_version_returns_none() -> None:
    xml_bytes = b'<?xml version="1.0"?><OWASPZAPReport></OWASPZAPReport>'
    ing = ZapIngestor()
    assert ing.extract_scanner_version(xml_bytes) is None


def test_zap_malformed_xml_returns_none() -> None:
    ing = ZapIngestor()
    assert ing.extract_scanner_version(b"<broken") is None


def test_burp_pulls_version_from_xml(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "burp_sample.xml"
    raw = fixture.read_bytes()
    ing = BurpIngestor()
    version = ing.extract_scanner_version(raw)
    assert version == "2023.10.3.7"


def test_burp_missing_version_returns_none() -> None:
    xml_bytes = b'<?xml version="1.0"?><issues></issues>'
    ing = BurpIngestor()
    assert ing.extract_scanner_version(xml_bytes) is None


def test_burp_malformed_xml_returns_none() -> None:
    ing = BurpIngestor()
    assert ing.extract_scanner_version(b"<broken") is None


def test_cppcheck_pulls_version_from_xml() -> None:
    raw = (Path(__file__).parent / "fixtures" / "cppcheck_real.xml").read_bytes()
    assert CppcheckIngestor().extract_scanner_version(raw) == "1.61"


def test_cppcheck_pulls_version_from_modern_xml() -> None:
    raw = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n<results version="2">'
        b'<cppcheck version="2.17.1"/><errors/></results>'
    )
    assert CppcheckIngestor().extract_scanner_version(raw) == "2.17.1"


def test_cppcheck_missing_version_returns_none() -> None:
    raw = b'<?xml version="1.0"?><results version="2"><cppcheck/><errors/></results>'
    assert CppcheckIngestor().extract_scanner_version(raw) is None


def test_cppcheck_malformed_xml_returns_none() -> None:
    assert CppcheckIngestor().extract_scanner_version(b"<broken") is None
