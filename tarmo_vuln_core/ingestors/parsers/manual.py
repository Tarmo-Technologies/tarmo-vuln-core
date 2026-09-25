"""Manual YAML/JSON finding ingestor."""

from __future__ import annotations

from pathlib import Path

import yaml

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory


class ManualIngestor(BaseIngestor):
    """Parses manually authored YAML or JSON finding files."""

    category = FindingCategory.MANUAL

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".yaml", ".yml", ".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file has a .yaml, .yml, or .json suffix."""
        if not path.exists():
            return False
        return path.suffix.lower() in {".yaml", ".yml", ".json"}

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a YAML or JSON manual finding file and return Finding objects.

        The file must contain a YAML/JSON list of finding mappings. Each mapping
        must include at minimum: id, title, severity, description, impact, remediation.

        Args:
            path: Path to the YAML or JSON finding file.

        Returns:
            List of validated Finding objects.

        Raises:
            IngestorError: If the file cannot be read, parsed, or validated.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            with path.open() as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise IngestorError(f"Failed to parse YAML: {e}") from e

        if not isinstance(data, list):
            raise IngestorError(
                f"Expected a YAML list of findings in {path}, got {type(data).__name__}"
            )

        findings: list[Finding] = []
        for i, raw in enumerate(data):
            if not isinstance(raw, dict):
                raise IngestorError(f"Finding #{i} is not a mapping: {raw!r}")
            try:
                raw.setdefault("source_tool", "manual")
                raw.setdefault("evidence", [])
                raw.setdefault("affected_hosts", [])
                finding = Finding.model_validate(raw)
            except Exception as e:
                raise IngestorError(f"Invalid finding #{i} in {path}: {e}") from e
            findings.append(finding)

        return findings
