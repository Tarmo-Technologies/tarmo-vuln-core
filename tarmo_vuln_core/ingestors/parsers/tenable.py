"""Tenable.io JSON vulnerability export ingestor."""

from __future__ import annotations

import json
import re
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
    "none": Severity.INFO,
}

_SEVERITY_ID_MAP: dict[int, Severity] = {
    4: Severity.CRITICAL,
    3: Severity.HIGH,
    2: Severity.MEDIUM,
    1: Severity.LOW,
    0: Severity.INFO,
}

_DEFAULT_DESCRIPTION = "A vulnerability was identified on the target system."
_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected host."
_DEFAULT_REMEDIATION = "Apply vendor-recommended patches and follow security hardening guidelines."


def _parse_cwe(plugin: dict) -> int | None:
    """Extract CWE ID from plugin.xref list (e.g. 'CWE-326' → 326)."""
    for ref in plugin.get("xref", []):
        m = re.match(r"CWE-(\d+)", str(ref), re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None


def _host_label(asset: dict) -> str:
    """Return the best host label from an asset dict (ipv4 > fqdn > hostname)."""
    return asset.get("ipv4") or asset.get("fqdn") or asset.get("hostname") or "unknown"


class TenableIngestor(BaseIngestor):
    """Parses Tenable.io JSON vulnerability export files.

    Tenable.io vulnerability exports are produced via the Tenable.io API or
    the platform's Export → Vulnerabilities → JSON workflow.  Each file has a
    top-level ``"vulnerabilities"`` array where each entry contains ``plugin``
    and ``asset`` sub-objects.

    Findings with the same plugin ID are deduplicated: all affected hosts are
    merged into a single ``Finding.affected_hosts`` list.
    """

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Tenable.io JSON export.

        Checks for a top-level ``"vulnerabilities"`` key whose first entry
        has both ``"plugin"`` and ``"asset"`` sub-keys.
        """
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities")
            if not isinstance(vulns, list) or not vulns:
                return False
            first = vulns[0]
            return isinstance(first, dict) and "plugin" in first and "asset" in first
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Tenable.io JSON export and return deduplicated Findings.

        Vulnerabilities with the same plugin ID are merged across hosts,
        collecting all distinct host labels in ``affected_hosts``.

        CVSS v3 scores are preferred over CVSS v2 when both are present.

        Args:
            path: Path to the Tenable.io JSON export file.

        Returns:
            List of Finding objects, one per unique plugin ID.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Tenable JSON: {e}") from e

        # Group by plugin ID
        plugin_data: dict[str, dict] = {}

        for vuln in data.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            plugin = vuln.get("plugin", {})
            asset = vuln.get("asset", {})

            plugin_id = str(plugin.get("id", "")).strip()
            if not plugin_id:
                continue

            host = _host_label(asset)

            if plugin_id not in plugin_data:
                # Prefer CVSSv3, fall back to CVSSv2
                cvss3 = plugin.get("cvss3_base_score")
                cvss2 = plugin.get("cvss_base_score")
                cvss3_vec = plugin.get("cvss3_vector")
                cvss2_vec = plugin.get("cvss_vector")

                cvss_score: float | None = None
                cvss_vector: str | None = None
                if cvss3 is not None:
                    try:
                        cvss_score = float(cvss3)
                        cvss_vector = str(cvss3_vec) if cvss3_vec else None
                    except (ValueError, TypeError):
                        pass
                if cvss_score is None and cvss2 is not None:
                    try:
                        cvss_score = float(cvss2)
                        cvss_vector = str(cvss2_vec) if cvss2_vec else None
                    except (ValueError, TypeError):
                        pass

                # Severity: string field preferred, fall back to severity_id
                sev_str = str(vuln.get("severity", "")).lower()
                severity = _SEVERITY_MAP.get(sev_str)
                if severity is None:
                    sev_id = vuln.get("severity_id")
                    if sev_id is not None:
                        severity = _SEVERITY_ID_MAP.get(int(sev_id), Severity.INFO)
                    else:
                        severity = Severity.INFO

                plugin_data[plugin_id] = {
                    "title": plugin.get("name") or f"Plugin {plugin_id}",
                    "description": plugin.get("description") or _DEFAULT_DESCRIPTION,
                    "remediation": plugin.get("solution") or _DEFAULT_REMEDIATION,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cwe_id": _parse_cwe(plugin),
                    "hosts": [],
                }

            hosts_list: list[str] = plugin_data[plugin_id]["hosts"]
            if host and host not in hosts_list:
                hosts_list.append(host)

        findings: list[Finding] = []
        for plugin_id, info in plugin_data.items():
            findings.append(
                Finding(
                    id=f"tenable-{_slugify(info['title'])}",
                    title=str(info["title"]),
                    severity=info["severity"],
                    description=str(info["description"]),
                    impact=_DEFAULT_IMPACT,
                    remediation=str(info["remediation"]),
                    cvss_score=info["cvss_score"],
                    cvss_vector=info["cvss_vector"],
                    cwe_id=info["cwe_id"],
                    affected_hosts=list(info["hosts"]),
                    source_tool="tenable",
                    raw_ref=plugin_id,
                )
            )

        return findings
