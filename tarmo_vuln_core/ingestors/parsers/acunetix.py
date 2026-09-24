"""Acunetix/Invicti web application scanner XML output ingestor."""

from __future__ import annotations

import contextlib
import re
from pathlib import Path

from tarmo_vuln_core.ingestors._xml import parse_xml_file, xml_first_tag
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "info": Severity.INFO,
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    text = _HTML_TAG_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def _module_slug(module_name: str) -> str:
    """Derive a short slug from an Acunetix module name or path."""
    # Take the last path component and strip the file extension
    part = module_name.strip("/").split("/")[-1]
    part = re.sub(r"\.\w+$", "", part)
    slug = re.sub(r"[^a-z0-9]+", "-", part.lower()).strip("-")
    return f"acunetix-{slug}" if slug else "acunetix-unknown"


class AcunetixIngestor(BaseIngestor):
    """Parses Acunetix/Invicti XML export files (``ScanGroup`` format)."""

    category = FindingCategory.DAST

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is an Acunetix XML export.

        Checks for a ``ScanGroup`` root element containing at least one
        ``Scan`` child.
        """
        if not path.exists():
            return False
        if path.suffix.lower() != ".xml":
            return False
        try:
            return xml_first_tag(path, fmt="Acunetix") == "ScanGroup"
        except IngestorError:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse an Acunetix XML export and return normalised findings.

        Processes all ``Scan/ReportItems/ReportItem`` elements in a
        ``ScanGroup`` file. Multiple scans in the same export are handled;
        findings with the same module slug are deduplicated and their
        ``affected_hosts`` lists are merged.

        Args:
            path: Path to the Acunetix XML export file.

        Returns:
            List of Finding objects.

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        root = parse_xml_file(path, fmt="Acunetix")
        if root.tag != "ScanGroup":
            raise IngestorError(f"Expected ScanGroup root element, got {root.tag!r}")

        findings_map: dict[str, Finding] = {}

        for scan in root.findall("Scan"):
            host = (scan.findtext("StartURL") or "").rstrip("/")

            report_items = scan.find("ReportItems")
            if report_items is None:
                continue

            for item in report_items.findall("ReportItem"):
                title = (item.findtext("Name") or "").strip()
                if not title:
                    continue

                module = (item.findtext("ModuleName") or "").strip()
                if module:
                    slug = _module_slug(module)
                else:
                    slug_base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
                    slug = f"acunetix-{slug_base[:60]}"

                sev_raw = (item.findtext("Severity") or "").lower()
                severity = _SEVERITY_MAP.get(sev_raw, Severity.INFO)

                description = _strip_html(item.findtext("Description") or "")
                impact = _strip_html(item.findtext("Impact") or "")
                remediation = _strip_html(item.findtext("Recommendation") or "")

                # CVSS3 data
                cvss_score: float | None = None
                cvss_vector: str | None = None
                cvss3 = item.find("CVSS3")
                if cvss3 is not None:
                    score_txt = (cvss3.findtext("Score") or "").strip()
                    if score_txt:
                        with contextlib.suppress(ValueError):
                            cvss_score = float(score_txt)
                    desc_txt = (cvss3.findtext("Descriptor") or "").strip()
                    cvss_vector = desc_txt or None

                # CWE (first entry only)
                cwe_id: int | None = None
                cwelist = item.find("CWEList")
                if cwelist is not None:
                    first_cwe = cwelist.findtext("CWEId")
                    if first_cwe:
                        with contextlib.suppress(ValueError):
                            cwe_id = int(first_cwe.strip())

                # CVE (first entry only, used as raw_ref)
                raw_ref: str | None = None
                cvelist = item.find("CVEList")
                if cvelist is not None:
                    first_cve = cvelist.findtext("CVEId")
                    if first_cve:
                        raw_ref = first_cve.strip()

                finding = Finding(
                    id=slug,
                    title=title,
                    severity=severity,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe_id=cwe_id,
                    owasp_id=None,
                    affected_hosts=[host] if host else [],
                    source_tool="acunetix",
                    raw_ref=raw_ref,
                )

                if slug not in findings_map:
                    findings_map[slug] = finding
                else:
                    existing = findings_map[slug]
                    merged = list(dict.fromkeys(existing.affected_hosts + finding.affected_hosts))
                    findings_map[slug] = existing.model_copy(update={"affected_hosts": merged})

        return list(findings_map.values())
