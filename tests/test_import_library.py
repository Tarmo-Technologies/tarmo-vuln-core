"""Tests for tarmo_vuln_core.library.import_library — DefectDojo and Ghostwriter importers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from tarmo_vuln_core.library.import_library import (
    _append_entries,
    _existing_ids,
    _normalise_severity,
    import_from_defectdojo,
    import_from_ghostwriter,
)

# ---------------------------------------------------------------------------
# _normalise_severity
# ---------------------------------------------------------------------------


class TestNormaliseSeverity:
    def test_critical(self) -> None:
        assert _normalise_severity("critical") == "CRITICAL"

    def test_high(self) -> None:
        assert _normalise_severity("High") == "HIGH"

    def test_medium(self) -> None:
        assert _normalise_severity("medium") == "MEDIUM"

    def test_moderate_maps_to_medium(self) -> None:
        assert _normalise_severity("moderate") == "MEDIUM"

    def test_low(self) -> None:
        assert _normalise_severity("LOW") == "LOW"

    def test_informational(self) -> None:
        assert _normalise_severity("informational") == "INFO"

    def test_info(self) -> None:
        assert _normalise_severity("info") == "INFO"

    def test_none_maps_to_info(self) -> None:
        assert _normalise_severity("none") == "INFO"

    def test_unknown_defaults_to_medium(self) -> None:
        assert _normalise_severity("bogus") == "MEDIUM"


# ---------------------------------------------------------------------------
# _existing_ids
# ---------------------------------------------------------------------------


class TestExistingIds:
    def test_returns_empty_set_when_file_missing(self, tmp_path: Path) -> None:
        result = _existing_ids(tmp_path / "nonexistent.yaml")
        assert result == set()

    def test_reads_ids_from_yaml_list(self, tmp_path: Path) -> None:
        lib_file = tmp_path / "lib.yaml"
        lib_file.write_text(
            yaml.dump([{"id": "sql-injection"}, {"id": "xss-stored"}]),
            encoding="utf-8",
        )
        result = _existing_ids(lib_file)
        assert result == {"sql-injection", "xss-stored"}

    def test_ignores_non_dict_entries(self, tmp_path: Path) -> None:
        lib_file = tmp_path / "lib.yaml"
        lib_file.write_text(
            yaml.dump([{"id": "xss"}, "not-a-dict", {"id": "sqli"}]),
            encoding="utf-8",
        )
        result = _existing_ids(lib_file)
        assert result == {"xss", "sqli"}

    def test_returns_empty_set_on_corrupt_yaml(self, tmp_path: Path) -> None:
        lib_file = tmp_path / "lib.yaml"
        lib_file.write_text("{{{not valid yaml", encoding="utf-8")
        result = _existing_ids(lib_file)
        assert result == set()

    def test_returns_empty_set_when_yaml_is_scalar(self, tmp_path: Path) -> None:
        lib_file = tmp_path / "lib.yaml"
        lib_file.write_text("just a string", encoding="utf-8")
        result = _existing_ids(lib_file)
        assert result == set()


# ---------------------------------------------------------------------------
# _append_entries
# ---------------------------------------------------------------------------


class TestAppendEntries:
    def test_creates_new_file(self, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "lib.yaml"
        _append_entries([{"id": "a", "title": "A"}], out)
        assert out.exists()
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        assert data[0]["id"] == "a"

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        out.write_text(
            yaml.dump([{"id": "old", "title": "Old"}]),
            encoding="utf-8",
        )
        _append_entries([{"id": "new", "title": "New"}], out)
        text = out.read_text(encoding="utf-8")
        # Both entries should be present in the file text
        assert "old" in text
        assert "new" in text


# ---------------------------------------------------------------------------
# import_from_defectdojo
# ---------------------------------------------------------------------------


def _mock_defectdojo_response(results: list[dict[str, Any]]) -> MagicMock:
    """Build a mock urllib response for DefectDojo."""
    body = json.dumps({"results": results}).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestImportFromDefectDojo:
    def test_imports_basic_template(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        templates = [
            {
                "title": "SQL Injection",
                "severity": "High",
                "description": "An SQL injection flaw.",
                "impact": "Full database compromise.",
                "mitigation": "Use parameterized queries.",
                "cwe": 89,
                "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "tags": ["injection", "owasp-top10"],
                "references": "https://owasp.org/sqli\nhttps://cwe.mitre.org/89",
            }
        ]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out)

        assert stats == {"new": 1, "skipped": 0, "failed": 0}
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        entry = data[0]
        assert entry["id"] == "sql-injection"
        assert entry["title"] == "SQL Injection"
        assert entry["severity"] == "HIGH"
        assert entry["description"] == "An SQL injection flaw."
        assert entry["impact"] == "Full database compromise."
        assert entry["remediation"] == "Use parameterized queries."
        assert entry["cwe_id"] == 89
        assert entry["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert entry["tags"] == ["injection", "owasp-top10"]
        assert entry["references"] == [
            "https://owasp.org/sqli",
            "https://cwe.mitre.org/89",
        ]

    def test_skips_duplicate_ids(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        out.write_text(
            yaml.dump([{"id": "sql-injection", "title": "SQL Injection"}]),
            encoding="utf-8",
        )
        templates = [{"title": "SQL Injection", "severity": "High"}]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out)

        assert stats == {"new": 0, "skipped": 1, "failed": 0}

    def test_fails_on_empty_title(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        templates = [{"title": "", "severity": "High"}, {"title": "   ", "severity": "Low"}]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out)

        assert stats["failed"] == 2
        assert stats["new"] == 0

    def test_dry_run_does_not_write(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "lib.yaml"
        templates = [{"title": "XSS Reflected", "severity": "Medium"}]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out, dry_run=True)

        assert stats["new"] == 1
        assert not out.exists()
        captured = capsys.readouterr()
        assert "xss-reflected" in captured.out
        assert "MEDIUM" in captured.out

    def test_defaults_for_missing_optional_fields(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        templates = [{"title": "Bare Finding"}]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out)

        assert stats["new"] == 1
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        entry = data[0]
        assert entry["severity"] == "MEDIUM"
        assert entry["description"] == "See reference."
        assert entry["impact"] == "Impact not specified."
        assert entry["remediation"] == "Remediation not specified."
        assert "cwe_id" not in entry
        assert "cvss_vector" not in entry
        assert "tags" not in entry
        assert "references" not in entry

    def test_tags_string_wrapped_in_list(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        templates = [{"title": "Tag Test", "severity": "Low", "tags": "single-tag"}]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            import_from_defectdojo("https://dojo.test", "tok", out)

        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert data[0]["tags"] == ["single-tag"]

    def test_api_failure_raises_valueerror(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        with (
            patch("urllib.request.urlopen", side_effect=ConnectionError("refused")),
            pytest.raises(ValueError, match="DefectDojo API call failed"),
        ):
            import_from_defectdojo("https://dojo.test", "tok", out)

    def test_multiple_templates_mixed_results(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        out.write_text(
            yaml.dump([{"id": "xss-stored", "title": "XSS Stored"}]),
            encoding="utf-8",
        )
        templates = [
            {"title": "XSS Stored", "severity": "High"},  # skipped (dup)
            {"title": "CSRF Missing Token", "severity": "Medium"},  # new
            {"title": "", "severity": "High"},  # failed (no title)
        ]
        mock_resp = _mock_defectdojo_response(templates)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_defectdojo("https://dojo.test", "tok", out)

        assert stats == {"new": 1, "skipped": 1, "failed": 1}


# ---------------------------------------------------------------------------
# import_from_ghostwriter
# ---------------------------------------------------------------------------


def _mock_ghostwriter_response(findings: list[dict[str, Any]]) -> MagicMock:
    """Build a mock urllib response for Ghostwriter GraphQL."""
    body = json.dumps({"data": {"findings": findings}}).encode()
    resp = MagicMock()
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestImportFromGhostwriter:
    def test_imports_basic_finding(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        findings = [
            {
                "title": "Insecure Direct Object Reference",
                "severity": {"severity": "High"},
                "description": "IDOR allows access to other users' data.",
                "impact": "Unauthorized data access.",
                "mitigation": "Enforce server-side authorization checks.",
                "references": "https://owasp.org/idor\nhttps://example.com/ref",
                "findingType": {"findingType": "Web"},
            }
        ]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats == {"new": 1, "skipped": 0, "failed": 0}
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        entry = data[0]
        assert entry["id"] == "insecure-direct-object-reference"
        assert entry["title"] == "Insecure Direct Object Reference"
        assert entry["severity"] == "HIGH"
        assert entry["description"] == "IDOR allows access to other users' data."
        assert entry["impact"] == "Unauthorized data access."
        assert entry["remediation"] == "Enforce server-side authorization checks."
        assert entry["references"] == [
            "https://owasp.org/idor",
            "https://example.com/ref",
        ]

    def test_skips_duplicate_ids(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        out.write_text(
            yaml.dump([{"id": "insecure-direct-object-reference"}]),
            encoding="utf-8",
        )
        findings = [
            {
                "title": "Insecure Direct Object Reference",
                "severity": {"severity": "High"},
            }
        ]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats == {"new": 0, "skipped": 1, "failed": 0}

    def test_fails_on_empty_title(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        findings = [{"title": "", "severity": {"severity": "Low"}}]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats["failed"] == 1
        assert stats["new"] == 0

    def test_dry_run_does_not_write(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "lib.yaml"
        findings = [{"title": "Open Redirect", "severity": {"severity": "Low"}}]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out, dry_run=True)

        assert stats["new"] == 1
        assert not out.exists()
        captured = capsys.readouterr()
        assert "open-redirect" in captured.out

    def test_severity_defaults_when_missing(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        findings = [{"title": "No Severity Given"}]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats["new"] == 1
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert data[0]["severity"] == "MEDIUM"

    def test_severity_non_dict_defaults_to_medium(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        findings = [{"title": "Severity String", "severity": "High"}]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats["new"] == 1
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        # severity is not a dict, so sev_raw stays "" and defaults to MEDIUM
        assert data[0]["severity"] == "MEDIUM"

    def test_defaults_for_missing_optional_fields(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        findings = [{"title": "Bare GW Finding"}]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            import_from_ghostwriter("https://gw.test", "tok", out)

        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        entry = data[0]
        assert entry["description"] == "See reference."
        assert entry["impact"] == "Impact not specified."
        assert entry["remediation"] == "Remediation not specified."
        assert "references" not in entry

    def test_api_failure_raises_valueerror(self, tmp_path: Path) -> None:
        out = tmp_path / "lib.yaml"
        with (
            patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")),
            pytest.raises(ValueError, match="Ghostwriter API call failed"),
        ):
            import_from_ghostwriter("https://gw.test", "tok", out)

    def test_multiple_findings_deduplicates_within_batch(self, tmp_path: Path) -> None:
        """Two findings with the same title in one batch — second should be skipped."""
        out = tmp_path / "lib.yaml"
        findings = [
            {"title": "Same Finding", "severity": {"severity": "High"}},
            {"title": "Same Finding", "severity": {"severity": "Low"}},
        ]
        mock_resp = _mock_ghostwriter_response(findings)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            stats = import_from_ghostwriter("https://gw.test", "tok", out)

        assert stats["new"] == 1
        assert stats["skipped"] == 1
