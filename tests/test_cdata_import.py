"""Tests for importing built-in CData defaults from CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["CWE", "Confidence", "Type", "Tool CWE", "Scanner"],
        )
        writer.writeheader()
        writer.writerows(rows)


class TestScannerNormalization:
    def test_normalizes_cppcheck_versions(self) -> None:
        from tarmo_vuln_core.cdata.import_defaults import normalize_scanner_name

        assert normalize_scanner_name("CppCheck 2.18.0") == "cppcheck"
        assert normalize_scanner_name("CppCheck V8.2") == "cppcheck"

    def test_normalizes_srm_versions(self) -> None:
        from tarmo_vuln_core.cdata.import_defaults import normalize_scanner_name

        assert normalize_scanner_name("SRM v2025.3.2") == "srm"


class TestImportDefaults:
    def test_import_adds_missing_cppcheck_row(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.cdata.import_defaults import import_defaults_from_csv

        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        (mappings_dir / "cppcheck.json").write_text("{}", encoding="utf-8")

        csv_path = tmp_path / "rows.csv"
        _write_csv(
            csv_path,
            [
                {
                    "CWE": "710",
                    "Confidence": "Inform",
                    "Type": "constVariablePointer",
                    "Tool CWE": "398",
                    "Scanner": "CppCheck 2.18.0",
                }
            ],
        )

        summary = import_defaults_from_csv(csv_path, mappings_dir=mappings_dir)
        data = json.loads((mappings_dir / "cppcheck.json").read_text(encoding="utf-8"))

        assert summary.rows_imported == 1
        assert data["constVariablePointer"]["cwe"] == 710
        assert data["constVariablePointer"]["confidence"] == "Inform"

    def test_import_creates_new_srm_mapping_file(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.cdata.import_defaults import import_defaults_from_csv

        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()

        csv_path = tmp_path / "rows.csv"
        _write_csv(
            csv_path,
            [
                {
                    "CWE": "561",
                    "Confidence": "Inform",
                    "Type": "Dead Code",
                    "Tool CWE": "561",
                    "Scanner": "SRM v2025.3.2",
                }
            ],
        )

        summary = import_defaults_from_csv(csv_path, mappings_dir=mappings_dir)
        data = json.loads((mappings_dir / "srm.json").read_text(encoding="utf-8"))

        assert summary.tools_created == ["srm"]
        assert data["Dead Code"]["cwe"] == 561
        assert data["Dead Code"]["confidence"] == "Inform"

    def test_import_skips_invalid_owasp_rows(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.cdata.import_defaults import import_defaults_from_csv

        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()

        csv_path = tmp_path / "rows.csv"
        _write_csv(
            csv_path,
            [
                {
                    "CWE": "CVE-2021-3711",
                    "Confidence": "Inform",
                    "Type": "",
                    "Tool CWE": "120",
                    "Scanner": "OWASP Dependency Check 12.1.0",
                }
            ],
        )

        summary = import_defaults_from_csv(csv_path, mappings_dir=mappings_dir)

        assert summary.rows_imported == 0
        assert summary.rows_skipped_invalid == 1

    def test_import_does_not_overwrite_existing_entries(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.cdata.import_defaults import import_defaults_from_csv

        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        (mappings_dir / "cppcheck.json").write_text(
            json.dumps({"constVariablePointer": {"cwe": 999}}),
            encoding="utf-8",
        )

        csv_path = tmp_path / "rows.csv"
        _write_csv(
            csv_path,
            [
                {
                    "CWE": "710",
                    "Confidence": "Inform",
                    "Type": "constVariablePointer",
                    "Tool CWE": "398",
                    "Scanner": "CppCheck 2.18.0",
                }
            ],
        )

        summary = import_defaults_from_csv(csv_path, mappings_dir=mappings_dir)
        data = json.loads((mappings_dir / "cppcheck.json").read_text(encoding="utf-8"))

        assert summary.rows_skipped_existing == 1
        assert data["constVariablePointer"]["cwe"] == 999
