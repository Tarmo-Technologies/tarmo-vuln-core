"""Unit tests for the PyLint JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.pylint_ingestor import PylintIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestPylintIngestor:
    def setup_method(self) -> None:
        self.ingestor = PylintIngestor()

    def test_can_handle_pylint(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "pylint_sample.json") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        assert len(findings) == 3

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        assert all(f.source_tool == "pylint" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        assert all(f.id.startswith("pylint-") for f in findings)

    def test_error_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        error_f = [f for f in findings if f.title == "undefined-variable"][0]
        assert error_f.severity == Severity.MEDIUM

    def test_warning_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        warn_f = [f for f in findings if f.title == "unused-import"][0]
        assert warn_f.severity == Severity.LOW

    def test_convention_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        conv_f = [f for f in findings if f.title == "missing-module-docstring"][0]
        assert conv_f.severity == Severity.INFO

    def test_message_id_in_raw_ref(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        error_f = [f for f in findings if f.title == "undefined-variable"][0]
        assert error_f.raw_ref == "E0602"

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "pylint_sample.json")
        error_f = [f for f in findings if f.title == "undefined-variable"][0]
        assert error_f.source_code_refs[0].file_path == "myapp/views.py"
        assert error_f.source_code_refs[0].start_line == 33

    def test_convention_rule_picks_up_cdata_cwe_and_confidence(self, tmp_path: Path) -> None:
        report = [
            {
                "type": "convention",
                "message-id": "C0103",
                "symbol": "invalid-name",
                "message": 'Variable name "X" doesn\'t conform to snake_case naming style',
                "line": 7,
                "path": "pkg/app.py",
            }
        ]
        path = tmp_path / "pylint-c0103.json"
        path.write_text(json.dumps(report), encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 710
        assert findings[0].severity == Severity.INFO
        assert findings[0].extra_fields.get("cdata_confidence") == "Inform"

    def test_refactor_rule_can_be_downgraded_to_inform_via_cdata(self, tmp_path: Path) -> None:
        report = [
            {
                "type": "refactor",
                "message-id": "R1732",
                "symbol": "consider-using-with",
                "message": "Consider using 'with' for resource-allocating operations",
                "line": 9,
                "path": "pkg/app.py",
            }
        ]
        path = tmp_path / "pylint-r1732.json"
        path.write_text(json.dumps(report), encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 710
        assert findings[0].severity == Severity.INFO
        assert findings[0].extra_fields.get("cdata_confidence") == "Inform"
