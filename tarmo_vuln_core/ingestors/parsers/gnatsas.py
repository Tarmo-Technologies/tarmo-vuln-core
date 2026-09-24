"""GNAT SAS (CodePeer) SARIF ingestor — Ada-specific subclass of SarifIngestor."""

from __future__ import annotations

import json
from pathlib import Path

from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.models import Finding, FindingCategory

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


class GnatSasIngestor(SarifIngestor):
    """Parses GNAT SAS / CodePeer SARIF output files (Ada-specific)."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".sarif", ".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a SARIF report from GNAT SAS or CodePeer."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("version") != "2.1.0":
                return False
            runs = data.get("runs", [])
            if not isinstance(runs, list) or len(runs) == 0:
                return False
            driver = runs[0].get("tool", {}).get("driver", {})
            driver_name = driver.get("name", "").lower()
            return "gnat" in driver_name or "codepeer" in driver_name
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse GNAT SAS SARIF, set source_tool to gnatsas and default language to Ada."""
        findings = super().ingest(path)

        for f in findings:
            f.source_tool = "gnatsas"
            # Update ID prefix to gnatsas
            if f.id.startswith("sarif-"):
                f.id = "gnatsas-" + f.id[6:]
            # Set Ada as default language
            if "language" not in f.extra_fields:
                f.extra_fields["language"] = "Ada"

        return findings
