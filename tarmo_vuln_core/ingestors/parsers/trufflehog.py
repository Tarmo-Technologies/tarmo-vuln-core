"""TruffleHog JSON-lines ingestor."""

from __future__ import annotations

import json
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_DEFAULT_DESCRIPTION = "A secret or credential was detected by TruffleHog."
_DEFAULT_IMPACT = (
    "An attacker with access to the repository can extract the secret and "
    "use it to access the corresponding service or system."
)
_DEFAULT_REMEDIATION = (
    "Rotate the exposed secret immediately. Store secrets in environment "
    "variables or a secrets manager, not in source code."
)


def _extract_source_ref(item: dict) -> SourceCodeRef | None:
    """Extract a SourceCodeRef from TruffleHog SourceMetadata."""
    meta = item.get("SourceMetadata", {}).get("Data", {})

    # Git source
    git = meta.get("Git")
    if git:
        file_path = git.get("file", "")
        if file_path:
            return SourceCodeRef(
                file_path=file_path,
                start_line=git.get("line"),
                commit_sha=git.get("commit", ""),
                repository=git.get("repository", ""),
            )

    # Filesystem source
    fs = meta.get("Filesystem")
    if fs:
        file_path = fs.get("file", "")
        if file_path:
            return SourceCodeRef(file_path=file_path)

    return None


class TrufflehogIngestor(BaseIngestor):
    """Parses TruffleHog JSON-lines output files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".json", ".jsonl"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a TruffleHog JSON-lines report."""
        if not path.exists():
            return False
        try:
            first_line = path.read_text(encoding="utf-8").split("\n", 1)[0].strip()
            if not first_line:
                return False
            data = json.loads(first_line)
            return isinstance(data, dict) and "DetectorType" in data and "SourceMetadata" in data
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a TruffleHog JSON-lines file and return a list of Finding objects.

        Groups by DetectorName for dedup. Uses only Redacted field, NEVER Raw/RawV2.
        Verified secrets get CRITICAL severity; unverified get HIGH.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            raise IngestorError(f"Failed to read TruffleHog file: {e}") from e

        # Group by DetectorName
        groups: dict[str, dict] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(item, dict):
                continue

            detector_name = item.get("DetectorName", "")
            if not detector_name:
                continue

            if detector_name not in groups:
                groups[detector_name] = {
                    "verified": False,
                    "files": [],
                    "source_code_refs": [],
                    "redacted": "",
                }

            # If any occurrence is verified, mark the group as verified
            if item.get("Verified"):
                groups[detector_name]["verified"] = True

            # Use only Redacted, never Raw/RawV2
            if not groups[detector_name]["redacted"]:
                groups[detector_name]["redacted"] = item.get("Redacted", "")

            ref = _extract_source_ref(item)
            if ref:
                if ref.file_path not in groups[detector_name]["files"]:
                    groups[detector_name]["files"].append(ref.file_path)
                groups[detector_name]["source_code_refs"].append(ref)

        findings: list[Finding] = []

        for detector_name, group in groups.items():
            severity = Severity.CRITICAL if group["verified"] else Severity.HIGH
            verified_str = "Verified" if group["verified"] else "Unverified"
            occurrence_count = len(group["source_code_refs"])

            description = f"{verified_str} secret detected by TruffleHog ({detector_name})"
            if occurrence_count > 1:
                description = f"{description} — {occurrence_count} occurrences"

            findings.append(
                Finding(
                    id=f"trufflehog-{slugify(detector_name)}",
                    title=f"Secret Detected: {detector_name} ({verified_str})",
                    severity=severity,
                    description=description,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    affected_hosts=group["files"],
                    source_code_refs=group["source_code_refs"],
                    source_tool="trufflehog",
                    raw_ref=detector_name,
                )
            )

        return findings
