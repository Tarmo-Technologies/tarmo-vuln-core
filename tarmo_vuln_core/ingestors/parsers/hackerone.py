"""HackerOne report import ingestor."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity
from tarmo_vuln_core.utils import slugify as _slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

_DEFAULT_DESCRIPTION = "A vulnerability was reported via HackerOne."
_DEFAULT_REMEDIATION = "Remediate according to the vulnerability report details."


class HackerOneIngestor(BaseIngestor):
    """Parses HackerOne API report exports (JSON).

    HackerOne's API v1 exports reports as a JSON structure with a ``data``
    array where each entry has ``type == "report"`` and contains ``attributes``
    with the vulnerability details.

    Each entry is expected to contain:
    - ``id`` — HackerOne report ID
    - ``type`` — must be "report"
    - ``attributes.title`` — vulnerability title
    - ``attributes.state`` — report state (resolved, triaged, new, etc.)
    - ``attributes.severity_rating`` — "critical" / "high" / "medium" / "low"
    - ``attributes.vulnerability_information`` — optional prose description
    - ``attributes.weakness.id`` — optional CWE ID (integer)
    - ``attributes.structured_scope.asset_identifier`` — optional host
    - ``attributes.cve_ids`` — optional list of CVE strings
    - ``relationships.severity.data.attributes`` — optional CVSS details
    """

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a HackerOne report export JSON."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            entries = data.get("data", [])
            if not isinstance(entries, list) or not entries:
                return False
            first = entries[0]
            return (
                isinstance(first, dict)
                and first.get("type") == "report"
                and isinstance(first.get("attributes"), dict)
                and "title" in first["attributes"]
                and "state" in first["attributes"]
            )
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a HackerOne report export and return Findings.

        Args:
            path: Path to the HackerOne JSON file.

        Returns:
            List of Finding objects, one per report in the ``data`` array.

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise IngestorError(f"Failed to parse HackerOne JSON: {exc}") from exc

        findings: list[Finding] = []

        for entry in data.get("data", []):
            if not isinstance(entry, dict) or entry.get("type") != "report":
                continue

            attrs = entry.get("attributes", {})
            if not isinstance(attrs, dict):
                continue

            report_id = str(entry.get("id", "")).strip()
            title = str(attrs.get("title", "")).strip()
            if not title:
                continue

            sev_str = str(attrs.get("severity_rating", "high")).lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)

            description = (
                str(attrs.get("vulnerability_information", "")).strip() or _DEFAULT_DESCRIPTION
            )

            # CVSS from relationships
            cvss_score: float | None = None
            cvss_vector: str | None = None
            rel_sev = (
                entry.get("relationships", {})
                .get("severity", {})
                .get("data", {})
                .get("attributes", {})
            )
            if isinstance(rel_sev, dict):
                raw_score = rel_sev.get("score")
                if raw_score is not None:
                    with contextlib.suppress(ValueError, TypeError):
                        cvss_score = float(raw_score)
                cvss_vector = str(rel_sev.get("cvss_vector_string", "")).strip() or None

            # CWE
            weakness = attrs.get("weakness", {})
            cwe_id: int | None = None
            if isinstance(weakness, dict) and weakness.get("id") is not None:
                with contextlib.suppress(ValueError, TypeError):
                    cwe_id = int(weakness["id"])

            # CVE
            cve_ids = attrs.get("cve_ids", [])
            cve: str | None = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else None

            # Affected host from structured scope
            scope = attrs.get("structured_scope", {})
            host: str | None = None
            if isinstance(scope, dict):
                host = str(scope.get("asset_identifier", "")).strip() or None
            affected_hosts = [host] if host else []

            raw_ref = cve or (f"H1-{report_id}" if report_id else None)
            finding_id = f"hackerone-{report_id}" if report_id else f"hackerone-{_slugify(title)}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=severity,
                    description=description,
                    impact=(
                        f"Vulnerability reported on {host}. "
                        "Exploitation may lead to unauthorized access or data exposure."
                        if host
                        else (
                            "Vulnerability exploitation may lead to "
                            "unauthorized access or data exposure."
                        )
                    ),
                    remediation=_DEFAULT_REMEDIATION,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe_id=cwe_id,
                    affected_hosts=affected_hosts,
                    source_tool="hackerone",
                    raw_ref=raw_ref,
                )
            )

        return findings
