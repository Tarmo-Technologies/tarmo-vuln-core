"""OWASP ZAP XML output ingestor."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import defusedxml.ElementTree as ET

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Instance, Severity
from tarmo_vuln_core.utils import get_xml_text as _get_text
from tarmo_vuln_core.utils import slugify as _slugify

_ZAP_SEVERITY_MAP: dict[str, Severity] = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

_DEFAULT_IMPACT = "The identified vulnerability may expose the application or its users to risk."
_DEFAULT_REMEDIATION = "Review the ZAP alert details and apply the recommended solution."


def _strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", text).strip()


def _parse_uri_to_instance(uri: str) -> Instance | None:
    """Parse a full URI into an Instance with host, port, and path."""
    parsed = urlparse(uri)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    return Instance(host=host, port=port, path=path) if host else None


class ZapIngestor(BaseIngestor):
    """Parses OWASP ZAP XML report files."""

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is an OWASP ZAP XML report.

        Checks that the XML root element is <OWASPZAPReport>.
        """
        if not path.exists():
            return False
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "OWASPZAPReport"
        except ET.ParseError:
            return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return None
        v = root.attrib.get("version")
        return str(v) if v else None

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a ZAP XML report and return findings grouped by plugin ID.

        Alert items with the same pluginid are merged into a single Finding
        with all affected URIs collected across all <site> elements.

        Args:
            path: Path to a ZAP XML report file.

        Returns:
            List of Finding objects, one per unique pluginid observed.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise IngestorError(f"Failed to parse ZAP XML: {e}") from e

        root = tree.getroot()

        # pluginid -> metadata dict with accumulated instances
        plugin_data: dict[str, dict[str, object]] = {}

        for site in root.findall("site"):
            alerts_el = site.find("alerts")
            if alerts_el is None:
                continue
            for alertitem in alerts_el.findall("alertitem"):
                pluginid = _get_text(alertitem, "pluginid")
                if not pluginid:
                    continue

                if pluginid not in plugin_data:
                    alert_name = _get_text(alertitem, "alert")
                    riskcode = _get_text(alertitem, "riskcode", "0")

                    desc_raw = _get_text(alertitem, "desc")
                    description = _strip_html(desc_raw) if desc_raw else _DEFAULT_IMPACT

                    solution_raw = _get_text(alertitem, "solution")
                    remediation = (
                        _strip_html(solution_raw) if solution_raw else _DEFAULT_REMEDIATION
                    )

                    cweid_str = _get_text(alertitem, "cweid")
                    cwe_id: int | None = None
                    if cweid_str and cweid_str.isdigit():
                        cwe_id = int(cweid_str)

                    plugin_data[pluginid] = {
                        "alert_name": alert_name,
                        "riskcode": riskcode,
                        "description": description,
                        "remediation": remediation,
                        "cwe_id": cwe_id,
                        "instances": {},  # (host, port, path) -> Instance
                    }

                instances_dict = cast(
                    dict[tuple[str, int, str], Instance], plugin_data[pluginid]["instances"]
                )
                instances_el = alertitem.find("instances")
                if instances_el is not None:
                    for instance_el in instances_el.findall("instance"):
                        uri = _get_text(instance_el, "uri")
                        if uri:
                            inst = _parse_uri_to_instance(uri)
                            if inst:
                                inst_key = (inst.host, inst.port or 80, inst.path or "/")
                                if inst_key not in instances_dict:
                                    instances_dict[inst_key] = inst

        findings: list[Finding] = []
        for pluginid, data in plugin_data.items():
            alert_name = str(data["alert_name"])
            riskcode = str(data["riskcode"])
            severity = _ZAP_SEVERITY_MAP.get(riskcode, Severity.INFO)
            instances = list(cast(dict[tuple[str, int, str], Instance], data["instances"]).values())
            affected_hosts = list(dict.fromkeys(inst.host for inst in instances))
            findings.append(
                Finding(
                    id=f"zap-{_slugify(alert_name)}",
                    title=alert_name,
                    severity=severity,
                    description=str(data["description"]),
                    impact=_DEFAULT_IMPACT,
                    remediation=str(data["remediation"]),
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=cast(int | None, data["cwe_id"]),
                    owasp_id=None,
                    affected_hosts=affected_hosts,
                    instances=instances,
                    source_tool="zap",
                    raw_ref=pluginid,
                )
            )

        return findings
