"""Burp Suite XML output ingestor."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import defusedxml.ElementTree as ET

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Instance, Severity
from tarmo_vuln_core.utils import get_xml_text as _get_text
from tarmo_vuln_core.utils import slugify as _slugify

_BURP_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "info": Severity.INFO,
}

_BURP_DEFAULT_IMPACT = (
    "Successful exploitation may allow an attacker to compromise the application, "
    "its data, or the underlying infrastructure."
)
_BURP_DEFAULT_REMEDIATION = (
    "Review the Burp Suite finding details and apply vendor-recommended remediation. "
    "Follow secure development guidelines for the affected technology."
)


class BurpIngestor(BaseIngestor):
    """Parses Burp Suite XML export files (Scanner issues)."""

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Burp Suite XML issues export.

        Checks that the XML root element is <issues>.
        """
        if not path.exists():
            return False
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "issues"
        except ET.ParseError:
            return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return None
        v = root.attrib.get("burpVersion")
        return str(v) if v else None

    def ingest(self, path: Path) -> list[Finding]:
        """Parse Burp Suite XML and return findings grouped by issue name.

        Issues with the same name are merged into a single Finding with all
        affected hosts collected.

        Args:
            path: Path to a Burp Suite XML export.

        Returns:
            List of Finding objects, one per unique issue name observed.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise IngestorError(f"Failed to parse Burp XML: {e}") from e

        root = tree.getroot()

        # name -> metadata dict with accumulated hosts and instances
        name_data: dict[str, dict[str, object]] = {}

        for issue in root.findall("issue"):
            name = _get_text(issue, "name")
            if not name:
                continue

            host_el = issue.find("host")
            ip = host_el.get("ip", "").strip() if host_el is not None else ""

            if name not in name_data:
                severity_str = _get_text(issue, "severity", "information")
                raw_ref = _get_text(issue, "type") or None

                bg = _get_text(issue, "issueBackground")
                description = bg if bg else _BURP_DEFAULT_IMPACT

                rem_bg = _get_text(issue, "remediationBackground")
                rem_detail = _get_text(issue, "remediationDetail")
                if rem_bg and rem_detail:
                    remediation = f"{rem_bg}\n\n{rem_detail}"
                elif rem_bg:
                    remediation = rem_bg
                elif rem_detail:
                    remediation = rem_detail
                else:
                    remediation = _BURP_DEFAULT_REMEDIATION

                name_data[name] = {
                    "hosts": [],
                    "instances": {},  # (ip, location) -> Instance
                    "severity_str": severity_str,
                    "description": description,
                    "remediation": remediation,
                    "raw_ref": raw_ref,
                }

            hosts_list = cast(list[str], name_data[name]["hosts"])
            if ip and ip not in hosts_list:
                hosts_list.append(ip)

            # Populate per-endpoint Instance using <location> (carries param context)
            location = _get_text(issue, "location") or _get_text(issue, "path") or None
            if ip:
                inst_key = (ip, location or "")
                instances_dict = cast(dict[tuple[str, str], Instance], name_data[name]["instances"])
                if inst_key not in instances_dict:
                    instances_dict[inst_key] = Instance(host=ip, path=location)

        findings: list[Finding] = []
        for name, data in name_data.items():
            severity = _BURP_SEVERITY_MAP.get(str(data["severity_str"]).lower(), Severity.INFO)
            instances = list(cast(dict[tuple[str, str], Instance], data["instances"]).values())
            findings.append(
                Finding(
                    id=f"burp-{_slugify(name)}",
                    title=name,
                    severity=severity,
                    description=str(data["description"]),
                    impact=_BURP_DEFAULT_IMPACT,
                    remediation=str(data["remediation"]),
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=cast(list[str], data["hosts"]),
                    instances=instances,
                    source_tool="burp",
                    raw_ref=data["raw_ref"],  # type: ignore[arg-type]
                )
            )

        return findings
