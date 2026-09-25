"""Metasploit CSV/XML output ingestor."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import cast
from xml.etree.ElementTree import Element

from tarmo_vuln_core.ingestors._xml import parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity
from tarmo_vuln_core.utils import get_xml_text as _get_text
from tarmo_vuln_core.utils import slugify as _slugify

_MSF_CSV_HEADER = "host,port,name,info,refs"
_MSF_XML_ROOTS = {"MetasploitV4", "MetasploitV5"}

_MSF_DEFAULT_IMPACT = (
    "Successful exploitation may allow an attacker to gain unauthorized access, "
    "escalate privileges, or compromise the target system."
)
_MSF_DEFAULT_REMEDIATION = (
    "Apply vendor-recommended patches and follow security hardening guidelines "
    "for the affected service or application."
)


class MetasploitIngestor(BaseIngestor):
    """Parses Metasploit Framework CSV or XML export files."""

    category = FindingCategory.INFRASTRUCTURE

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".csv", ".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Metasploit CSV or XML export."""
        if not path.exists():
            return False
        suffix = path.suffix.lower()

        if suffix == ".csv":
            try:
                first_line = path.read_text(errors="replace").splitlines()[0].strip().lower()
                return first_line.startswith(_MSF_CSV_HEADER)
            except (OSError, IndexError):
                return False

        if suffix == ".xml":
            try:
                return parse_xml_file(path, fmt="Metasploit").tag in _MSF_XML_ROOTS
            except IngestorError:
                return False

        return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Metasploit export and return findings.

        Args:
            path: Path to a Metasploit CSV or XML export.

        Returns:
            List of Finding objects.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        suffix = path.suffix.lower()
        if suffix == ".csv":
            return self._ingest_csv(path)
        if suffix == ".xml":
            return self._ingest_xml(path)
        raise IngestorError(f"Unsupported file format: {path.suffix}")

    def _ingest_xml(self, path: Path) -> list[Finding]:
        """Parse Metasploit XML and return findings.

        Supports both flat top-level schema (vulns/vuln, services/service) and the
        host-nested schema (hosts/host/vulns/vuln, hosts/host/services/service).
        """
        root = parse_xml_file(path, fmt="Metasploit")

        # --- Collect vuln elements with their associated host address ---
        # key: vuln name → metadata + accumulated hosts
        vuln_data: dict[str, dict[str, object]] = {}

        def _process_vuln(vuln: Element, host_addr: str) -> None:
            name = _get_text(vuln, "name")
            if not name:
                return
            if name not in vuln_data:
                refs_el = vuln.find("refs")
                raw_ref: str | None = None
                if refs_el is not None:
                    first_ref = refs_el.find("ref")
                    if first_ref is not None:
                        raw_ref = (first_ref.text or "").strip() or None
                info = _get_text(vuln, "info")
                vuln_data[name] = {
                    "hosts": [],
                    "description": info if info else _MSF_DEFAULT_IMPACT,
                    "raw_ref": raw_ref,
                }
            hosts_list = cast(list[str], vuln_data[name]["hosts"])
            if host_addr and host_addr not in hosts_list:
                hosts_list.append(host_addr)

        # Flat top-level: <vulns><vuln><host>IP</host>…</vuln></vulns>
        for vuln in root.findall("vulns/vuln"):
            _process_vuln(vuln, _get_text(vuln, "host"))

        # Host-nested: hosts/host/vulns/vuln — host address on parent <host> element
        for host in root.findall("hosts/host"):
            host_addr = _get_text(host, "address")
            for vuln in host.findall("vulns/vuln"):
                _process_vuln(vuln, host_addr)

        # --- Collect service elements with their associated host address ---
        # key: (name, port, proto) → metadata + accumulated hosts
        svc_data: dict[tuple[str, str, str], dict[str, object]] = {}

        def _process_service(svc: Element, host_addr: str) -> None:
            name = _get_text(svc, "name")
            if not name:
                return
            port = _get_text(svc, "port")
            proto = _get_text(svc, "proto", "tcp")
            key = (name, port, proto)
            if key not in svc_data:
                info = _get_text(svc, "info")
                description = (
                    info if info else f"Port {port}/{proto} ({name}) discovered by Metasploit."
                )
                svc_data[key] = {"hosts": [], "description": description}
            hosts_list = cast(list[str], svc_data[key]["hosts"])
            if host_addr and host_addr not in hosts_list:
                hosts_list.append(host_addr)

        # Flat top-level: <services><service><host>IP</host>…</service></services>
        for svc in root.findall("services/service"):
            _process_service(svc, _get_text(svc, "host"))

        # Host-nested: hosts/host/services/service — host address on parent <host> element
        for host in root.findall("hosts/host"):
            host_addr = _get_text(host, "address")
            for svc in host.findall("services/service"):
                _process_service(svc, host_addr)

        # Build Finding list
        findings: list[Finding] = []

        for name, data in vuln_data.items():
            findings.append(
                Finding(
                    id=f"msf-vuln-{_slugify(name)}",
                    title=name,
                    severity=Severity.HIGH,
                    description=str(data["description"]),
                    impact=_MSF_DEFAULT_IMPACT,
                    remediation=_MSF_DEFAULT_REMEDIATION,
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=cast(list[str], data["hosts"]),
                    source_tool="metasploit",
                    raw_ref=data["raw_ref"],  # type: ignore[arg-type]
                )
            )

        for (name, port, proto), data in svc_data.items():
            findings.append(
                Finding(
                    id=f"msf-service-{port}-{proto}-{_slugify(name)}",
                    title=f"{name.upper()} ({port}/{proto})",
                    severity=Severity.INFO,
                    description=str(data["description"]),
                    impact=_MSF_DEFAULT_IMPACT,
                    remediation=_MSF_DEFAULT_REMEDIATION,
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=cast(list[str], data["hosts"]),
                    source_tool="metasploit",
                    raw_ref=None,
                )
            )

        return findings

    def _ingest_csv(self, path: Path) -> list[Finding]:
        """Parse a Metasploit CSV export and return findings."""
        try:
            content = path.read_text(errors="replace")
        except OSError as e:
            raise IngestorError(f"Cannot read CSV file: {e}") from e

        reader = csv.DictReader(content.splitlines())

        # Group by (name, port) — accumulate unique host values
        group_data: dict[tuple[str, str], dict[str, object]] = {}

        for row in reader:
            name = (row.get("name") or "").strip()
            if not name:
                continue
            port = (row.get("port") or "").strip()
            host = (row.get("host") or "").strip()
            info = (row.get("info") or "").strip()
            refs = (row.get("refs") or "").strip()

            key = (name, port)
            if key not in group_data:
                group_data[key] = {
                    "hosts": [],
                    "description": "",
                    "raw_ref": None,
                }

            if info and not group_data[key]["description"]:
                group_data[key]["description"] = info
            if refs and group_data[key]["raw_ref"] is None:
                group_data[key]["raw_ref"] = refs

            hosts_list = cast(list[str], group_data[key]["hosts"])
            if host and host not in hosts_list:
                hosts_list.append(host)

        findings: list[Finding] = []

        for (name, port), data in group_data.items():
            description = str(data["description"]) or _MSF_DEFAULT_IMPACT
            title = f"{name} ({port})" if port else name
            findings.append(
                Finding(
                    id=f"msf-csv-{port}-{_slugify(name)}",
                    title=title,
                    severity=Severity.INFO,
                    description=description,
                    impact=_MSF_DEFAULT_IMPACT,
                    remediation=_MSF_DEFAULT_REMEDIATION,
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=cast(list[str], data["hosts"]),
                    source_tool="metasploit",
                    raw_ref=data["raw_ref"],  # type: ignore[arg-type]
                )
            )

        return findings
