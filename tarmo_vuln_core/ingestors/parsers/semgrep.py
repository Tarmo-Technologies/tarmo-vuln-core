"""Semgrep SARIF ingestor — thin subclass of SarifIngestor."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.models import Finding, FindingCategory

_SEMGREP_DRIVER = re.compile(r"semgrep(?: (?:oss|pro|ce))?", re.IGNORECASE)


class SemgrepIngestor(SarifIngestor):
    """Parses Semgrep SARIF output, tagging findings with source_tool='semgrep'."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".json", ".sarif"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a SARIF report produced by Semgrep."""
        if not super().can_handle(path):
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            runs = data.get("runs", [])
            if not runs:
                return False
            driver_name = runs[0].get("tool", {}).get("driver", {}).get("name", "")
            # Semgrep <1.x wrote "semgrep"; 1.160 writes "Semgrep OSS".
            return bool(_SEMGREP_DRIVER.fullmatch(str(driver_name).strip()))
        except Exception:
            return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            return None
        runs = obj.get("runs") if isinstance(obj, dict) else None
        if not runs or not isinstance(runs, list):
            return None
        driver = runs[0].get("tool", {}).get("driver", {}) if isinstance(runs[0], dict) else {}
        if not isinstance(driver, dict):
            return None
        # Semgrep writes SARIF driver.semanticVersion; older/other emitters use version.
        v = driver.get("semanticVersion") or driver.get("version")
        return str(v) if v else None

    def ingest(self, path: Path) -> list[Finding]:
        """Parse Semgrep SARIF and re-tag findings with semgrep source_tool and ID prefix."""
        findings = super().ingest(path)
        return [
            f.model_copy(
                update={
                    "source_tool": "semgrep",
                    "id": f.id.replace("sarif-", "semgrep-", 1),
                }
            )
            for f in findings
        ]
