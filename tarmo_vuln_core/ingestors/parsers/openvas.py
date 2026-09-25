"""OpenVAS/Greenbone Vulnerability Manager XML output ingestor."""

from __future__ import annotations

from pathlib import Path

from tarmo_vuln_core.ingestors._xml import parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity
from tarmo_vuln_core.utils import get_xml_text as _get_text
from tarmo_vuln_core.utils import slugify as _slugify

_THREAT_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,  # upgraded to CRITICAL if cvss_score >= 9.0
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Log": Severity.INFO,
    "Alarm": Severity.INFO,
}

_DEFAULT_DESCRIPTION = "A vulnerability was identified on the remote host."
_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected host."
_DEFAULT_REMEDIATION = "Review the OpenVAS finding details and apply the recommended solution."


def _parse_cvss_vector(tags: str) -> str | None:
    """Extract cvss_base_vector from pipe-separated OpenVAS tags string."""
    for part in tags.split("|"):
        if part.startswith("cvss_base_vector="):
            value = part[len("cvss_base_vector=") :].strip()
            return value if value else None
    return None


def _parse_solution(tags: str) -> str | None:
    """Extract solution from pipe-separated OpenVAS tags string."""
    for part in tags.split("|"):
        if part.startswith("solution="):
            value = part[len("solution=") :].strip()
            return value if value else None
    return None


def _clean_cve(cve_str: str) -> str | None:
    """Return first CVE ID from a string, or None if not a real CVE reference."""
    if not cve_str:
        return None
    stripped = cve_str.strip()
    if stripped.upper() in ("NOCVE", "NOBID", "NOXREF", ""):
        return None
    # May be comma-separated; take the first
    first = stripped.split(",")[0].strip()
    return first if first else None


class OpenvasIngestor(BaseIngestor):
    """Parses OpenVAS/Greenbone Vulnerability Manager XML report files."""

    category = FindingCategory.INFRASTRUCTURE

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is an OpenVAS XML report.

        Checks that the XML root element is <report> and that the file
        contains at least one <result> with an <nvt> child element,
        distinguishing OpenVAS reports from other XML formats.
        """
        if not path.exists():
            return False
        try:
            root = parse_xml_file(path, fmt="OpenVAS")
        except IngestorError:
            return False
        if root.tag != "report":
            return False
        return root.find(".//result/nvt") is not None

    def ingest(self, path: Path) -> list[Finding]:
        """Parse an OpenVAS XML report and return findings grouped by NVT OID.

        Results sharing the same NVT OID (or name for OID-less entries) are
        merged into a single Finding with all affected hosts collected.

        Args:
            path: Path to an OpenVAS XML report file.

        Returns:
            List of Finding objects, one per unique NVT OID (or name).

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        root = parse_xml_file(path, fmt="OpenVAS")

        # group_key → accumulated metadata dict
        group_data: dict[str, dict[str, object]] = {}
        # group_key → list of affected hosts (in insertion order, no dups)
        group_hosts: dict[str, list[str]] = {}

        for result in root.findall(".//result"):
            nvt = result.find("nvt")
            if nvt is None:
                continue

            oid: str = nvt.get("oid", "").strip()
            nvt_name: str = _get_text(nvt, "name")
            group_key: str = oid if oid else nvt_name
            if not group_key:
                continue

            host = _get_text(result, "host")

            if group_key not in group_data:
                threat = _get_text(result, "threat")
                severity_str = _get_text(result, "severity")
                try:
                    cvss_score: float | None = float(severity_str)
                except ValueError:
                    cvss_score = None

                base_severity = _THREAT_SEVERITY_MAP.get(threat, Severity.INFO)
                if base_severity == Severity.HIGH and cvss_score is not None and cvss_score >= 9.0:
                    base_severity = Severity.CRITICAL

                tags_str = _get_text(nvt, "tags")
                cvss_vector = _parse_cvss_vector(tags_str)
                solution = _parse_solution(tags_str)

                cve_str = _get_text(nvt, "cve")
                clean_cve = _clean_cve(cve_str)

                # raw_ref: prefer CVE, then OID, then NVT name
                if clean_cve:
                    raw_ref: str = clean_cve
                elif oid:
                    raw_ref = oid
                else:
                    raw_ref = nvt_name

                description = _get_text(result, "description") or _DEFAULT_DESCRIPTION
                remediation = solution or _DEFAULT_REMEDIATION

                group_data[group_key] = {
                    "title": nvt_name or group_key,
                    "severity": base_severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "description": description,
                    "remediation": remediation,
                    "raw_ref": raw_ref,
                }
                group_hosts[group_key] = []

            hosts_list: list[str] = group_hosts[group_key]
            if host and host not in hosts_list:
                hosts_list.append(host)

        findings: list[Finding] = []
        for group_key, data in group_data.items():
            slug = _slugify(str(data["raw_ref"]) or group_key)
            findings.append(
                Finding(
                    id=f"openvas-{slug}",
                    title=str(data["title"]),
                    severity=data["severity"],  # type: ignore[arg-type]
                    description=str(data["description"]),
                    impact=_DEFAULT_IMPACT,
                    remediation=str(data["remediation"]),
                    cvss_score=data["cvss_score"],  # type: ignore[arg-type]
                    cvss_vector=data["cvss_vector"],  # type: ignore[arg-type]
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=list(group_hosts[group_key]),
                    source_tool="openvas",
                    raw_ref=str(data["raw_ref"]),
                )
            )

        return findings
