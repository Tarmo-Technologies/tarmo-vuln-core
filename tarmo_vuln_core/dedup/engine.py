"""Pure-Python dedup engine — used when Rust extension is not available."""

from __future__ import annotations

import hashlib
from typing import Any


def _finding_hash_key(finding: dict[str, Any]) -> str:
    """Compute a deterministic hash key for a finding dict.

    Key fields: id, title, severity, sorted affected_hosts, description.
    """
    parts = "|".join(
        [
            str(finding.get("id", "")),
            str(finding.get("title", "")),
            str(finding.get("severity", "")),
            ",".join(sorted(finding.get("affected_hosts", []))),
            str(finding.get("description", "")),
        ]
    )
    return hashlib.sha256(parts.encode()).hexdigest()


def python_deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings based on content hash. Preserves first-seen order."""
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        key = _finding_hash_key(finding)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
