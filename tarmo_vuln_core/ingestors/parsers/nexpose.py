"""Rapid7 Nexpose / InsightVM XML export ingestor."""

from __future__ import annotations

import contextlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity

#: Nexpose severity is an integer 1–10.
_SEVERITY_MAP: list[tuple[int, Severity]] = [
    (9, Severity.CRITICAL),
    (7, Severity.HIGH),
    (4, Severity.MEDIUM),
    (1, Severity.LOW),
]

#: Test statuses indicating the host is actually affected.
_VULNERABLE_STATUSES = frozenset({"vulnerable-exploited", "vulnerable-version"})


def _severity(score: int) -> Severity:
    """Map a Nexpose integer severity (1–10) to a Severity enum value."""
    for threshold, sev in _SEVERITY_MAP:
        if score >= threshold:
            return sev
    return Severity.INFO


def _element_text(elem: ET.Element | None) -> str:
    """Return all text content from an element's subtree, collapsed."""
    if elem is None:
        return ""
    text = " ".join(elem.itertext())
    return re.sub(r"\s+", " ", text).strip()


class NexposeIngestor(BaseIngestor):
    """Parses Rapid7 Nexpose / InsightVM XML export files (``NexposeReport`` format)."""

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Nexpose XML report.

        Checks for a ``NexposeReport`` root element (or the legacy
        ``NexposeSimpleXML`` root used by older Nexpose versions).
        """
        if not path.exists():
            return False
        if path.suffix.lower() != ".xml":
            return False
        try:
            for _event, elem in ET.iterparse(str(path), events=("start",)):  # nosec B314
                return elem.tag in ("NexposeReport", "NexposeSimpleXML")
        except ET.ParseError:
            return False
        return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Nexpose XML export and return normalised findings.

        Only vulnerabilities with at least one ``vulnerable-exploited`` or
        ``vulnerable-version`` test result across any node are returned.
        Findings are grouped by vulnerability ``id`` — affected hosts are
        merged across all nodes.

        Args:
            path: Path to the Nexpose XML report file.

        Returns:
            List of Finding objects (one per unique vulnerability ID).

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            tree = ET.parse(str(path))  # nosec B314
        except ET.ParseError as exc:
            raise IngestorError(f"Failed to parse Nexpose XML: {exc}") from exc

        root = tree.getroot()
        if root.tag not in ("NexposeReport", "NexposeSimpleXML"):
            raise IngestorError(f"Expected NexposeReport root element, got {root.tag!r}")

        # ── Step 1: Build vulnerability definitions map ──────────────────────
        vuln_defs: dict[str, ET.Element] = {
            v.get("id", ""): v
            for v in root.findall("VulnerabilityDefinitions/vulnerability")
            if v.get("id")
        }

        # ── Step 2: Map vuln_id → [affected_host_addresses] ──────────────────
        vuln_hosts: dict[str, list[str]] = {}
        for node in root.findall("nodes/node"):
            address = node.get("address", "")
            for test in node.findall(".//test"):
                if test.get("status") not in _VULNERABLE_STATUSES:
                    continue
                vid = test.get("id", "")
                if not vid:
                    continue
                hosts = vuln_hosts.setdefault(vid, [])
                if address and address not in hosts:
                    hosts.append(address)

        # ── Step 3: Build Findings ────────────────────────────────────────────
        findings: list[Finding] = []
        for vid, hosts in vuln_hosts.items():
            vd = vuln_defs.get(vid)
            if vd is None:
                # Vuln ID referenced in tests but no definition — emit minimal finding
                findings.append(
                    Finding(
                        id=f"nexpose-{re.sub(r'[^a-z0-9]+', '-', vid.lower())}",
                        title=vid,
                        severity=Severity.INFO,
                        description=f"Nexpose reported vulnerability: {vid}",
                        impact="",
                        remediation="",
                        cvss_score=None,
                        cvss_vector=None,
                        cwe_id=None,
                        owasp_id=None,
                        affected_hosts=hosts,
                        source_tool="nexpose",
                        raw_ref=None,
                    )
                )
                continue

            title = vd.get("title", vid)

            sev_raw = vd.get("severity", "0")
            try:
                sev_int = int(sev_raw)
            except ValueError:
                sev_int = 0
            severity = _severity(sev_int)

            cvss_score: float | None = None
            cvss_raw = vd.get("cvssScore", "")
            if cvss_raw:
                with contextlib.suppress(ValueError):
                    cvss_score = float(cvss_raw)

            # Strip parentheses from the CVSS vector string if present
            cvss_vector: str | None = None
            cv_raw = (vd.get("cvssVector") or "").strip().strip("()")
            cvss_vector = cv_raw if cv_raw else None

            description = _element_text(vd.find("description"))
            remediation = _element_text(vd.find("solution"))

            # CVE references
            cve_refs = [
                r.text.strip()
                for r in vd.findall("references/reference")
                if r.get("source") == "CVE" and r.text
            ]
            raw_ref = cve_refs[0] if cve_refs else None

            slug = f"nexpose-{re.sub(r'[^a-z0-9]+', '-', vid.lower()).strip('-')}"

            findings.append(
                Finding(
                    id=slug,
                    title=title,
                    severity=severity,
                    description=description,
                    impact="",
                    remediation=remediation,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=hosts,
                    source_tool="nexpose",
                    raw_ref=raw_ref,
                )
            )

        return findings
