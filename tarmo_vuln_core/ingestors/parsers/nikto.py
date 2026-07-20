"""Nikto web server scanner XML output ingestor."""

from __future__ import annotations

import re
from pathlib import Path

import defusedxml.ElementTree as ET

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity
from tarmo_vuln_core.utils import slugify as _slugify

_NIKTO_DEFAULT_IMPACT = (
    "Successful exploitation may allow an attacker to gather intelligence about "
    "the target server, access sensitive files, or exploit known vulnerabilities."
)
_NIKTO_DEFAULT_REMEDIATION = (
    "Review the Nikto finding details and apply the appropriate remediation. "
    "Follow secure configuration guidelines for the affected technology."
)

# Ordered: more specific keyword patterns first; last entry is the default.
_SEVERITY_PATTERNS: list[tuple[str, Severity]] = [
    (r"remote code execution|rce\b|arbitrary code", Severity.CRITICAL),
    (r"sql injection|blind sql|sqli\b", Severity.HIGH),
    (r"cross[ -]?site scripting|xss\b|script.*alert", Severity.HIGH),
    (r"directory (listing|traversal|index)|path traversal", Severity.MEDIUM),
    (
        r"default (file|page|install|configuration|jsp|pages?)|phpinfo|test (file|page)",
        Severity.MEDIUM,
    ),  # noqa: E501
    (r"content[- ]security[- ]policy|csp\b", Severity.MEDIUM),
    (r"x[- ]frame[- ]options|clickjack", Severity.LOW),
    (r"x[- ]content[- ]type[- ]options", Severity.LOW),
    (r"httponly|samesite|secure flag|cookie.*flag|flag.*cookie", Severity.LOW),
    (r"trace\b|http trace|track\b", Severity.LOW),
    (r"put method|delete method|allow.*header.*put|allow.*header.*delete", Severity.LOW),
    (r"allowed http method", Severity.LOW),
    (r"server.*version|banner|identifies.*server|leaks.*inode|etag", Severity.INFO),
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _infer_severity(description: str) -> Severity:
    """Return a severity level inferred from the Nikto item description."""
    lower = description.lower()
    for pattern, sev in _SEVERITY_PATTERNS:
        if re.search(pattern, lower):
            return sev
    return Severity.INFO


def _extract_cve(text: str) -> str | None:
    """Return the first CVE ID found in text, or None."""
    m = _CVE_RE.search(text)
    return m.group(0).upper() if m else None


def _title_from_desc(desc: str) -> str:
    """Extract a concise title from a Nikto item description."""
    # Take up to the first sentence-ending punctuation or 80 chars
    for sep in (".", "!", "?", "\n"):
        idx = desc.find(sep)
        if 0 < idx <= 80:
            return desc[:idx].strip()
    return desc[:80].strip()


def _repair_truncated_xml(path: Path) -> str:
    """Attempt to repair truncated Nikto XML by appending missing closing tags.

    Nikto processes killed by timeout produce valid ``<item>`` elements but
    are missing the final ``</scandetails></niktoscan>`` closing tags.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    stripped = raw.rstrip()
    # Append whichever closing tags are missing
    if "</scandetails>" not in stripped:
        stripped += "\n</scandetails>"
    if "</niktoscan>" not in stripped:
        stripped += "\n</niktoscan>"
    return stripped


class NiktoIngestor(BaseIngestor):
    """Parses Nikto web server scanner XML output files."""

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Nikto XML output (root element ``niktoscan``).

        Nikto produces XML via ``nikto -o results.xml -Format xml``. The root
        element is ``<niktoscan>`` (or a ``<niktoscan>`` wrapper containing
        nested ``<niktoscan>`` elements for multi-target scans).

        Also handles truncated XML from timeout-killed Nikto processes by
        attempting to repair missing closing tags.
        """
        if not path.exists():
            return False
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            return root.tag == "niktoscan"
        except ET.ParseError:
            try:
                repaired = _repair_truncated_xml(path)
                root = ET.fromstring(repaired)
                return root.tag == "niktoscan"
            except ET.ParseError:
                return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse Nikto XML and return deduplicated findings.

        Items with the same Nikto ID *and* description across multiple
        ``<scandetails>`` sections (multi-target scans) are merged into a
        single Finding with all affected hosts collected.

        Args:
            path: Path to a Nikto XML output file.

        Returns:
            List of Finding objects.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError:
            try:
                repaired = _repair_truncated_xml(path)
                root = ET.fromstring(repaired)
            except ET.ParseError as exc:
                raise IngestorError(f"Failed to parse Nikto XML: {exc}") from exc

        # (nikto_id, description) -> accumulated data dict
        item_data: dict[tuple[str, str], dict] = {}

        for scandetails in root.findall(".//scandetails"):
            targetip = scandetails.get("targetip", "")
            targetport = scandetails.get("targetport", "")
            targethostname = scandetails.get("targethostname", "")

            # Build host string: prefer IP but fall back to hostname
            base = targetip or targethostname
            host = f"{base}:{targetport}" if base and targetport else base

            for item in scandetails.findall("item"):
                nikto_id = item.get("id", "")
                desc = (item.findtext("description") or "").strip()
                if not desc:
                    continue

                key = (nikto_id, desc)
                if key not in item_data:
                    refs_text = (item.findtext("references") or "").strip()
                    cve = _extract_cve(desc) or (_extract_cve(refs_text) if refs_text else None)
                    item_data[key] = {
                        "nikto_id": nikto_id,
                        "description": desc,
                        "raw_ref": cve,
                        "hosts": [],
                    }

                hosts_list: list[str] = item_data[key]["hosts"]
                if host and host not in hosts_list:
                    hosts_list.append(host)

        used_ids: set[str] = set()
        findings: list[Finding] = []

        for (nikto_id, desc), data in item_data.items():
            severity = _infer_severity(desc)
            base_id = f"nikto-{nikto_id}" if nikto_id else f"nikto-{_slugify(desc[:40])}"
            final_id = base_id
            counter = 2
            while final_id in used_ids:
                final_id = f"{base_id}-{counter}"
                counter += 1
            used_ids.add(final_id)

            findings.append(
                Finding(
                    id=final_id,
                    title=_title_from_desc(desc),
                    severity=severity,
                    description=desc,
                    impact=_NIKTO_DEFAULT_IMPACT,
                    remediation=_NIKTO_DEFAULT_REMEDIATION,
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id=None,
                    affected_hosts=data["hosts"],
                    source_tool="nikto",
                    raw_ref=data["raw_ref"],
                )
            )

        return findings
