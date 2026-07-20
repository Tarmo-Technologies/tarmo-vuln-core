"""BloodHound AD attack-path findings ingestor."""

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
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_DEFAULT_DESCRIPTION = "An Active Directory attack path was identified."
_DEFAULT_REMEDIATION = "Follow Microsoft AD hardening guidelines to remediate this finding."


class BloodHoundIngestor(BaseIngestor):
    """Parses BloodHound CE attack-path findings exports (JSON).

    BloodHound CE can export attack-path findings as a JSON file with a
    ``meta`` block (``type == "bloodhoundfinding"``) and a ``data`` array
    where each entry describes one attack path or AD misconfiguration.

    Each entry is expected to contain:
    - ``FindingType`` — title of the attack path
    - ``Domain`` — Active Directory domain name
    - ``Severity`` — "Critical" / "High" / "Medium" / "Low"
    - ``AffectedNodes`` — list of affected hosts / accounts
    - ``Description`` — optional prose
    - ``Remediation`` — optional remediation guidance
    - ``CWE`` — optional integer CWE ID
    - ``CVE`` — optional CVE reference string
    """

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a BloodHound findings JSON export."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            meta = data.get("meta", {})
            return (
                isinstance(data.get("data"), list)
                and str(meta.get("type", "")).lower() == "bloodhoundfinding"
            )
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a BloodHound findings JSON export and return Findings.

        Args:
            path: Path to the BloodHound findings JSON file.

        Returns:
            List of Finding objects, one per entry in the ``data`` array.

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise IngestorError(f"Failed to parse BloodHound JSON: {exc}") from exc

        findings: list[Finding] = []

        for entry in data.get("data", []):
            if not isinstance(entry, dict):
                continue

            finding_type = str(entry.get("FindingType", "Unknown AD Finding")).strip()
            if not finding_type:
                continue

            domain = str(entry.get("Domain", "")).strip()
            sev_str = str(entry.get("Severity", "high")).lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)

            nodes: list[str] = [str(n) for n in entry.get("AffectedNodes", []) if n]
            description = str(entry.get("Description", "")).strip() or _DEFAULT_DESCRIPTION
            remediation = str(entry.get("Remediation", "")).strip() or _DEFAULT_REMEDIATION

            cwe_raw = entry.get("CWE")
            cwe_id: int | None = None
            if cwe_raw is not None:
                with contextlib.suppress(ValueError, TypeError):
                    cwe_id = int(cwe_raw)

            cve = str(entry.get("CVE", "")).strip() or None
            raw_ref = cve or (domain if domain else None)

            # Prepend domain to affected hosts if not already present
            if domain and not nodes:
                nodes = [domain]

            findings.append(
                Finding(
                    id=f"bloodhound-{_slugify(finding_type)}",
                    title=finding_type,
                    severity=severity,
                    description=description,
                    impact=(
                        f"Active Directory attack path identified in domain {domain}. "
                        "Exploitation may allow privilege escalation to Domain Admin or "
                        "lateral movement across the environment."
                        if domain
                        else "Active Directory attack path may allow privilege escalation."
                    ),
                    remediation=remediation,
                    cwe_id=cwe_id,
                    affected_hosts=nodes,
                    source_tool="bloodhound",
                    raw_ref=raw_ref,
                )
            )

        return findings
