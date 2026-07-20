"""Nessus .nessus XML output ingestor."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

import defusedxml.ElementTree as ET

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Host, HostProperty, Severity
from tarmo_vuln_core.utils import get_xml_text as _get_text

logger = logging.getLogger(__name__)

_NESSUS_SEVERITY_MAP: dict[str, Severity] = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "4": Severity.CRITICAL,
}

_NESSUS_DEFAULT_IMPACT = (
    "The vulnerability may allow an attacker to compromise the affected system "
    "or intercept sensitive information."
)

_NESSUS_DEFAULT_REMEDIATION = (
    "Apply vendor-recommended patches and follow security hardening guidelines "
    "for the affected service or application."
)


class NessusIngestor(BaseIngestor):
    """Parses Nessus .nessus XML export files."""

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".nessus"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a .nessus XML export.

        Checks the file suffix and that the XML root element is <NessusClientData_v2>.
        """
        if not path.exists():
            return False
        if path.suffix.lower() != ".nessus":
            return False
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "NessusClientData_v2"
        except ET.ParseError:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a .nessus file and return findings grouped by plugin ID.

        All hosts affected by the same Nessus plugin are collected into a
        single Finding's affected_hosts list.

        Args:
            path: Path to a .nessus XML export.

        Returns:
            List of Finding objects, one per unique plugin ID observed.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        if path.suffix.lower() != ".nessus":
            raise IngestorError(f"Expected .nessus suffix, got: {path.suffix}")
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise IngestorError(f"Failed to parse .nessus XML: {e}") from e

        root = tree.getroot()

        # plugin_id -> metadata dict including accumulated hosts list
        plugin_data: dict[str, dict[str, object]] = {}

        for report in root.findall("Report"):
            for report_host in report.findall("ReportHost"):
                # Resolve host IP from HostProperties, fall back to name attribute
                ip: str = ""
                host_props = report_host.find("HostProperties")
                if host_props is not None:
                    for tag_el in host_props.findall("tag"):
                        if tag_el.get("name") == "host-ip":
                            ip = (tag_el.text or "").strip()
                            break
                if not ip:
                    ip = report_host.get("name", "")

                for item in report_host.findall("ReportItem"):
                    plugin_id = item.get("pluginID", "")
                    if not plugin_id:
                        continue

                    if plugin_id not in plugin_data:
                        plugin_name = item.get("pluginName", plugin_id)
                        severity_str = item.get("severity", "0")

                        description = _get_text(item, "description")
                        if not description:
                            description = _get_text(item, "synopsis", _NESSUS_DEFAULT_IMPACT)

                        remediation = _get_text(item, "solution", _NESSUS_DEFAULT_REMEDIATION)

                        cvss_str = _get_text(item, "cvss_base_score")
                        cvss_score: float | None = None
                        if cvss_str:
                            try:
                                cvss_score = float(cvss_str)
                            except ValueError:
                                logger.warning(
                                    "Invalid CVSS score %r in plugin %s; treating as None",
                                    cvss_str,
                                    plugin_id,
                                )

                        cvss_vector: str | None = _get_text(item, "cvss_vector") or None

                        cve_text = _get_text(item, "cve")
                        raw_ref = cve_text if cve_text else plugin_id

                        # Extract CWE if present
                        cwe_id: int | None = None
                        cwe_text = _get_text(item, "cwe")
                        if cwe_text and cwe_text.isdigit():
                            cwe_id = int(cwe_text)

                        plugin_data[plugin_id] = {
                            "hosts": [],
                            "plugin_name": plugin_name,
                            "severity_str": severity_str,
                            "description": description,
                            "remediation": remediation,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "raw_ref": raw_ref,
                            "cwe_id": cwe_id,
                        }

                    hosts_list = cast(list[str], plugin_data[plugin_id]["hosts"])
                    if ip and ip not in hosts_list:
                        hosts_list.append(ip)

        findings: list[Finding] = []
        for plugin_id, data in plugin_data.items():
            severity = _NESSUS_SEVERITY_MAP.get(str(data["severity_str"]), Severity.INFO)
            findings.append(
                Finding(
                    id=f"nessus-plugin-{plugin_id}",
                    title=str(data["plugin_name"]),
                    severity=severity,
                    description=str(data["description"]),
                    impact=_NESSUS_DEFAULT_IMPACT,
                    remediation=str(data["remediation"]),
                    cvss_score=data["cvss_score"],  # type: ignore[arg-type]
                    cvss_vector=data["cvss_vector"],  # type: ignore[arg-type]
                    affected_hosts=cast(list[str], data["hosts"]),
                    source_tool="nessus",
                    raw_ref=str(data["raw_ref"]),
                    cwe_id=data["cwe_id"],  # type: ignore[arg-type]
                )
            )

        return findings

    def ingest_hosts(self, path: Path) -> list[Host]:
        """Extract per-host metadata from a .nessus file's HostProperties blocks.

        Args:
            path: Path to a .nessus XML export.

        Returns:
            List of Host objects, one per ReportHost element found.
        """
        if not path.exists() or path.suffix.lower() != ".nessus":
            return []
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return []

        root = tree.getroot()
        hosts: list[Host] = []

        for report in root.findall("Report"):
            for report_host in report.findall("ReportHost"):
                # Resolve host IP
                ip: str = ""
                host_props = report_host.find("HostProperties")
                prop_map: dict[str, str] = {}
                if host_props is not None:
                    for tag_el in host_props.findall("tag"):
                        name = tag_el.get("name", "")
                        value = (tag_el.text or "").strip()
                        if name:
                            prop_map[name] = value
                        if name == "host-ip":
                            ip = value
                if not ip:
                    ip = report_host.get("name", "")
                if not ip:
                    continue

                hostnames: list[str] = []
                for hn_key in ("hostname", "netbios-name"):
                    val = prop_map.get(hn_key, "")
                    if val and val != ip and val not in hostnames:
                        hostnames.append(val)

                os_name = prop_map.get("operating-system") or prop_map.get("os") or None
                mac = prop_map.get("mac-address") or None

                # Expose remaining interesting properties
                _SKIP_KEYS = {
                    "host-ip",
                    "hostname",
                    "netbios-name",
                    "operating-system",
                    "os",
                    "mac-address",
                }
                properties: list[HostProperty] = []
                for key, val in prop_map.items():
                    if key not in _SKIP_KEYS and val:
                        properties.append(HostProperty(key=key, value=val))

                hosts.append(
                    Host(
                        address=ip,
                        hostnames=hostnames,
                        os=os_name,
                        mac=mac,
                        properties=properties,
                    )
                )

        return hosts
