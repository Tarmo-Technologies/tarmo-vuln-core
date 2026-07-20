"""Gitleaks JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_DEFAULT_DESCRIPTION = "A secret or credential was detected in source code by gitleaks."
_DEFAULT_IMPACT = (
    "An attacker with access to the repository can extract the secret and "
    "use it to access the corresponding service or system."
)
_DEFAULT_REMEDIATION = (
    "Rotate the exposed secret immediately. Store secrets in environment "
    "variables or a secrets manager, not in source code."
)


class GitleaksIngestor(BaseIngestor):
    """Parses gitleaks JSON output files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a gitleaks JSON report."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list) or not data:
                return False
            first = data[0]
            return isinstance(first, dict) and "RuleID" in first and "Fingerprint" in first
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a gitleaks JSON file and return a list of Finding objects.

        Groups occurrences by RuleID to avoid one-finding-per-occurrence.
        NEVER includes actual secret values in findings.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse gitleaks JSON: {e}") from e

        if not isinstance(data, list):
            return []

        # Group by RuleID
        groups: dict[str, dict] = {}

        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("RuleID", "")
            if not rule_id:
                continue

            if rule_id not in groups:
                groups[rule_id] = {
                    "description": item.get("Description", ""),
                    "files": [],
                    "source_code_refs": [],
                }

            file_path = item.get("File", "")
            if file_path and file_path not in groups[rule_id]["files"]:
                groups[rule_id]["files"].append(file_path)

            if file_path:
                groups[rule_id]["source_code_refs"].append(
                    SourceCodeRef(
                        file_path=file_path,
                        start_line=item.get("StartLine"),
                        end_line=item.get("EndLine"),
                        commit_sha=item.get("Commit", ""),
                    )
                )

        findings: list[Finding] = []

        for rule_id, group in groups.items():
            description = group["description"] or _DEFAULT_DESCRIPTION
            occurrence_count = len(group["source_code_refs"])
            if occurrence_count > 1:
                description = f"{description} ({occurrence_count} occurrences)"

            findings.append(
                Finding(
                    id=f"gitleaks-{slugify(rule_id)}",
                    title=f"Secret Detected: {group['description'] or rule_id}",
                    severity=Severity.HIGH,
                    description=description,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    affected_hosts=group["files"],
                    source_code_refs=group["source_code_refs"],
                    source_tool="gitleaks",
                    raw_ref=rule_id,
                )
            )

        return findings
