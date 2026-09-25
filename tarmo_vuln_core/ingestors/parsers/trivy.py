"""Trivy JSON output ingestor."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity
from tarmo_vuln_core.utils import slugify as _slugify

_TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_DEFAULT_DESCRIPTION = "A vulnerability was identified in an installed package."
_DEFAULT_IMPACT = (
    "The vulnerability may allow an attacker to compromise the affected container or system."
)
_DEFAULT_REMEDIATION = "Update the affected package to a non-vulnerable version."


def _extract_cvss(vuln: dict) -> tuple[float | None, str | None]:
    """Extract V3Score and V3Vector from CVSS data, preferring NVD."""
    cvss = vuln.get("CVSS", {})
    if not cvss:
        return None, None
    # Prefer NVD
    nvd = cvss.get("nvd", {})
    if nvd and "V3Score" in nvd:
        return nvd.get("V3Score"), nvd.get("V3Vector")
    # Fall back to first available vendor with V3Score
    for vendor_data in cvss.values():
        if "V3Score" in vendor_data:
            return vendor_data.get("V3Score"), vendor_data.get("V3Vector")
    return None, None


def _extract_cwe(vuln: dict) -> int | None:
    """Parse first CWE ID from CweIDs list (e.g. 'CWE-79' → 79)."""
    cwe_ids = vuln.get("CweIDs", [])
    if not cwe_ids:
        return None
    match = re.match(r"CWE-(\d+)", cwe_ids[0], re.IGNORECASE)
    return int(match.group(1)) if match else None


class TrivyIngestor(BaseIngestor):
    """Parses Trivy JSON output files (trivy image/fs/repo --format json)."""

    category = FindingCategory.SCA

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Trivy JSON report.

        Checks that the JSON has a 'Results' key that is a list with at least
        one entry containing a 'Vulnerabilities' key.
        """
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            results = data.get("Results", [])
            if not isinstance(results, list) or not results:
                return False
            return any("Vulnerabilities" in r for r in results)
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Trivy JSON report and return findings grouped by CVE ID.

        Vulnerabilities with the same VulnerabilityID are merged across
        Results (targets), collecting all targets in affected_hosts.

        Args:
            path: Path to a Trivy JSON output file.

        Returns:
            List of Finding objects, one per unique VulnerabilityID.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            raw = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Trivy JSON: {e}") from e

        # Group by VulnerabilityID, collecting targets as affected_hosts
        vuln_data: dict[str, dict] = {}

        for result in raw.get("Results", []):
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities", []):
                vid = vuln.get("VulnerabilityID", "")
                if not vid:
                    continue

                if vid not in vuln_data:
                    cvss_score, cvss_vector = _extract_cvss(vuln)
                    title = vuln.get("Title") or vid
                    description = vuln.get("Description") or _DEFAULT_DESCRIPTION
                    fixed_version = vuln.get("FixedVersion", "")
                    pkg_name = vuln.get("PkgName", "")
                    if fixed_version:
                        remediation = f"Update {pkg_name} to version {fixed_version}."
                    else:
                        remediation = _DEFAULT_REMEDIATION

                    vuln_data[vid] = {
                        "severity": _TRIVY_SEVERITY_MAP.get(
                            vuln.get("Severity", ""), Severity.INFO
                        ),
                        "title": title,
                        "description": description,
                        "remediation": remediation,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "cwe_id": _extract_cwe(vuln),
                        "targets": [],
                    }

                targets_list: list[str] = vuln_data[vid]["targets"]
                if target and target not in targets_list:
                    targets_list.append(target)

        findings: list[Finding] = []
        for vid, info in vuln_data.items():
            findings.append(
                Finding(
                    id=f"trivy-{_slugify(vid)}",
                    title=str(info["title"]),
                    severity=info["severity"],
                    description=str(info["description"]),
                    impact=_DEFAULT_IMPACT,
                    remediation=str(info["remediation"]),
                    cvss_score=info["cvss_score"],
                    cvss_vector=info["cvss_vector"],
                    cwe_id=info["cwe_id"],
                    owasp_id=None,
                    affected_hosts=list(info["targets"]),
                    source_tool="trivy",
                    raw_ref=vid,
                )
            )

        return findings
