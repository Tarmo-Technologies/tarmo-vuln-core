"""Nmap XML output ingestor."""

from __future__ import annotations

from pathlib import Path
from typing import cast
from xml.etree.ElementTree import Element

from tarmo_vuln_core.ingestors._xml import parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Host, HostProperty, Severity

_NMAP_IMPACT = (
    "An open port exposes the running service to network-level attacks. "
    "If the service is unnecessary or misconfigured, it may be exploited "
    "to gain unauthorized access."
)
_NMAP_REMEDIATION = (
    "Verify that this service is required for business operations. "
    "If not needed, disable the service and close the port via firewall rules. "
    "If required, ensure the service is patched and properly configured."
)


def _host_ip(host: Element) -> str | None:
    """Return the first IPv4/IPv6 address for a host element, or None."""
    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr")
    return None


_HTTP_SIGS = ("http/1.", "http/1\\.", "http/2", "express", "nginx", "apache", "node.js")


def _looks_like_http(svc_el: Element, port_el: Element) -> bool:
    """Detect HTTP on non-standard ports via service fingerprint data."""
    # Check service element attributes
    for attr in ("product", "extrainfo", "servicefp"):
        val = (svc_el.get(attr) or "").lower()
        if any(sig in val for sig in _HTTP_SIGS):
            return True
    # Check <script> child elements for decoded fingerprint text
    for script in port_el.findall("script"):
        output = (script.get("output") or "").lower()
        if any(sig in output for sig in _HTTP_SIGS):
            return True
        for elem in script.findall("elem"):
            if any(sig in (elem.text or "").lower() for sig in _HTTP_SIGS):
                return True
    return False


class NmapIngestor(BaseIngestor):
    """Parses Nmap XML output files (nmap -oX)."""

    category = FindingCategory.INFRASTRUCTURE

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a valid Nmap XML report.

        Checks that the XML root element is <nmaprun>.
        """
        if not path.exists():
            return False
        try:
            return parse_xml_file(path, fmt="Nmap").tag == "nmaprun"
        except IngestorError:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse Nmap XML and return one Finding per unique open port.

        Findings are grouped by (protocol, portid): all hosts exposing
        the same port are collected into a single Finding's affected_hosts.

        Args:
            path: Path to an Nmap XML file.

        Returns:
            List of Finding objects, one per open port observed.

        Raises:
            IngestorError: If the file cannot be parsed as Nmap XML.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        root = parse_xml_file(path, fmt="Nmap")

        # (protocol, portid) -> {hosts, service_name, product, version}
        port_data: dict[tuple[str, str], dict[str, object]] = {}

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            ip = _host_ip(host)
            if not ip:
                continue

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                protocol = port.get("protocol", "tcp")
                portid = port.get("portid", "0")
                key = (protocol, portid)

                svc = port.find("service")
                service_name = svc.get("name", "unknown") if svc is not None else "unknown"
                # Detect HTTP on non-standard ports (#189)
                if (
                    svc is not None
                    and service_name not in ("http", "https")
                    and _looks_like_http(svc, port)
                ):
                    service_name = "http"
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""

                if key not in port_data:
                    port_data[key] = {
                        "hosts": [],
                        "service_name": service_name,
                        "product": product,
                        "version": version,
                    }

                hosts_list = cast(list[str], port_data[key]["hosts"])
                if ip not in hosts_list:
                    hosts_list.append(ip)

        findings: list[Finding] = []
        for (protocol, portid), data in port_data.items():
            service_name = str(data["service_name"])
            product = str(data["product"])
            version = str(data["version"])
            hosts = cast(list[str], data["hosts"])

            if product:
                service_detail = f"{product} {version}".strip() if version else product
            else:
                service_detail = service_name

            description = (
                f"Port {portid}/{protocol} is open and running {service_detail}. "
                "This port was identified during network scanning."
            )

            findings.append(
                Finding(
                    id=f"nmap-open-{protocol}-{portid}",
                    title=f"Open Port: {portid}/{protocol} ({service_name})",
                    severity=Severity.INFO,
                    description=description,
                    impact=_NMAP_IMPACT,
                    remediation=_NMAP_REMEDIATION,
                    affected_hosts=hosts,
                    source_tool="nmap",
                    cvss_score=None,
                    raw_ref=None,
                )
            )

        return findings

    def ingest_hosts(self, path: Path) -> list[Host]:
        """Extract per-host metadata (OS, hostnames, open ports) from Nmap XML.

        Args:
            path: Path to an Nmap XML file.

        Returns:
            List of Host objects, one per up host in the scan.
        """
        if not path.exists():
            return []
        try:
            root = parse_xml_file(path, fmt="Nmap")
        except IngestorError:
            return []
        hosts: list[Host] = []

        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue

            ip = _host_ip(host_el)
            if not ip:
                continue

            # Collect all hostnames
            hostnames: list[str] = []
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    name = hn.get("name", "")
                    if name and name not in hostnames:
                        hostnames.append(name)

            # MAC address from address elements
            mac: str | None = None
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "mac":
                    mac = addr_el.get("addr")

            # OS detection
            os_name: str | None = None
            os_confidence: int | None = None
            os_el = host_el.find("os")
            if os_el is not None:
                best_match = os_el.find("osmatch")
                if best_match is not None:
                    os_name = best_match.get("name")
                    try:
                        os_confidence = int(best_match.get("accuracy", "0"))
                    except ValueError:
                        os_confidence = None

            # Open ports as properties
            properties: list[HostProperty] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid = port_el.get("portid", "")
                    protocol = port_el.get("protocol", "tcp")
                    svc = port_el.find("service")
                    svc_name = svc.get("name", "") if svc is not None else ""
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    detail = f"{product} {version}".strip() if product else svc_name
                    properties.append(
                        HostProperty(
                            key=f"port/{portid}/{protocol}",
                            value=detail or f"{portid}/{protocol}",
                        )
                    )

            hosts.append(
                Host(
                    address=ip,
                    hostnames=hostnames,
                    os=os_name,
                    os_confidence=os_confidence,
                    mac=mac,
                    properties=properties,
                )
            )

        return hosts
