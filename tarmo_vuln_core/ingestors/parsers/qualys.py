"""Qualys ASSET_DATA_REPORT XML ingestor for pentest-scribe.

Parses Qualys vulnerability scan XML exports and generates one Finding per QID
(vulnerability ID), merging all affected hosts into the ``affected_hosts`` list.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity
from tarmo_vuln_core.utils import slugify as _slugify_base

logger = logging.getLogger(__name__)

_QUALYS_SEVERITY_MAP: dict[str, Severity] = {
    "1": Severity.INFO,
    "2": Severity.LOW,
    "3": Severity.MEDIUM,
    "4": Severity.HIGH,
    "5": Severity.CRITICAL,
}

_DEFAULT_DESCRIPTION = "See library entry for details."
_DEFAULT_IMPACT = (
    "The vulnerability may allow an attacker to compromise the affected system "
    "or access sensitive information."
)
_DEFAULT_REMEDIATION = (
    "Apply vendor-recommended patches and follow security hardening guidelines "
    "for the affected service."
)


def _slugify(text: str) -> str:
    """Convert a title to a slug usable as a finding ID."""
    return _slugify_base(text)[:80]


def _get_cdata(el: Element | None, tag: str, fallback: str = "") -> str:
    """Return stripped CDATA/text of a child element, or fallback."""
    if el is None:
        return fallback
    child = el.find(tag)
    return (child.text or fallback).strip() if child is not None else fallback


class QualysIngestor(BaseIngestor):
    """Ingestor for Qualys ASSET_DATA_REPORT XML export files.

    One finding is produced per unique QID. All hosts affected by the same
    QID are collected into a single Finding's ``affected_hosts`` list.
    Vulnerability metadata (title, severity, description, impact, remediation,
    CVEs) is sourced from the ``GLOSSARY/VULN_DETAILS_LIST`` section.
    """

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True for XML files with root element ``ASSET_DATA_REPORT``."""
        if not path.exists():
            return False
        if path.suffix.lower() != ".xml":
            return False
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "ASSET_DATA_REPORT"
        except ET.ParseError:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Qualys ASSET_DATA_REPORT XML file and return Finding objects.

        Args:
            path: Path to the Qualys XML export file.

        Returns:
            List of Finding objects, one per unique QID found.

        Raises:
            IngestorError: If the file cannot be parsed or is not a valid Qualys report.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            raise IngestorError(f"Cannot parse Qualys XML {path}: {exc}") from exc

        root = tree.getroot()
        if root.tag != "ASSET_DATA_REPORT":
            raise IngestorError(f"Not a valid Qualys ASSET_DATA_REPORT file: {path}")

        # --- Step 1: collect QID → hosts mapping from HOST_LIST ---
        # qid_hosts: { qid_str: list[str] }
        qid_hosts: dict[str, list[str]] = {}

        for host in root.findall(".//HOST"):
            ip_el = host.find("IP")
            dns_el = host.find("DNS")
            ip = ip_el.text.strip() if ip_el is not None and ip_el.text else "unknown"
            dns = dns_el.text.strip() if dns_el is not None and dns_el.text else ""
            host_str = f"{dns} ({ip})" if dns else ip

            for vuln_info in host.findall(".//VULN_INFO"):
                qid_el = vuln_info.find("QID")
                if qid_el is None or not qid_el.text:
                    continue
                qid = qid_el.text.strip()

                # Optionally qualify with port
                port_el = vuln_info.find("PORT")
                if port_el is not None and port_el.text:
                    entry_str = f"{host_str}:{port_el.text.strip()}"
                else:
                    entry_str = host_str

                hosts = qid_hosts.setdefault(qid, [])
                if entry_str not in hosts:
                    hosts.append(entry_str)

        if not qid_hosts:
            logger.debug("No VULN_INFO entries found in %s", path)
            return []

        # --- Step 2: enrich with GLOSSARY metadata ---
        # qid_meta: { qid_str: { title, severity, description, impact, remediation, cves } }
        qid_meta: dict[str, dict] = {}

        for vd in root.findall(".//VULN_DETAILS"):
            qid_el = vd.find("QID")
            if qid_el is None or not qid_el.text:
                continue
            qid = qid_el.text.strip()

            title_el = vd.find("TITLE")
            title = (
                title_el.text.strip() if title_el is not None and title_el.text else f"QID {qid}"
            )

            severity_el = vd.find("SEVERITY")
            sev_str = (
                severity_el.text.strip() if severity_el is not None and severity_el.text else "1"
            )
            severity = _QUALYS_SEVERITY_MAP.get(sev_str, Severity.INFO)

            # THREAT → description, IMPACT → impact, SOLUTION → remediation
            threat = _get_cdata(vd, "THREAT", _DEFAULT_DESCRIPTION)
            impact = _get_cdata(vd, "IMPACT", _DEFAULT_IMPACT)
            solution = _get_cdata(vd, "SOLUTION", _DEFAULT_REMEDIATION)

            # CVE list
            cves = [c.text.strip() for c in vd.findall(".//CVE_ID_LIST/CVE_ID/ID") if c.text]

            # CVSS score from GLOSSARY (prefer CVSS3_BASE, fall back to CVSS_BASE)
            cvss_score: float | None = None
            cvss3_base_el = vd.find(".//CVSS3_SCORE/CVSS3_BASE")
            _t3 = cvss3_base_el.text or "" if cvss3_base_el is not None else ""
            cvss3_raw = _t3.strip()
            if cvss3_raw and cvss3_raw not in ("-",):
                with contextlib.suppress(ValueError):
                    cvss_score = float(cvss3_raw)
            if cvss_score is None:
                cvss_base_el = vd.find(".//CVSS_SCORE/CVSS_BASE")
                _t = cvss_base_el.text or "" if cvss_base_el is not None else ""
                cvss_raw = _t.strip()
                if cvss_raw and cvss_raw not in ("-",):
                    with contextlib.suppress(ValueError):
                        cvss_score = float(cvss_raw)

            qid_meta[qid] = {
                "title": title,
                "severity": severity,
                "description": threat,
                "impact": impact,
                "remediation": solution,
                "cves": cves,
                "cvss_score": cvss_score,
            }

        # --- Step 3: build Finding objects ---
        findings: list[Finding] = []
        for qid, hosts in qid_hosts.items():
            meta = qid_meta.get(qid, {})
            title = meta.get("title", f"QID {qid}")
            severity = meta.get("severity", Severity.INFO)
            description = meta.get("description", _DEFAULT_DESCRIPTION)
            impact = meta.get("impact", _DEFAULT_IMPACT)
            remediation = meta.get("remediation", _DEFAULT_REMEDIATION)
            cves = meta.get("cves", [])
            cvss_score = meta.get("cvss_score")

            raw_ref = f"QID:{qid}"
            if cves:
                raw_ref = cves[0]  # prefer first CVE as the raw_ref for library matching

            finding_id = _slugify(title) or f"qualys-qid-{qid}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=severity,
                    affected_hosts=hosts,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    cvss_score=cvss_score,
                    source_tool="qualys",
                    raw_ref=raw_ref,
                )
            )

        logger.debug("QualysIngestor: produced %d findings from %s", len(findings), path)
        return findings
