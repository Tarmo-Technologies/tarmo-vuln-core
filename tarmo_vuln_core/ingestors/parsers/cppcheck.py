"""cppcheck XML ingestor."""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element

from tarmo_vuln_core.cdata import default_registry
from tarmo_vuln_core.ingestors._xml import parse_xml_bytes, parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "style": Severity.LOW,
    "performance": Severity.LOW,
    "portability": Severity.LOW,
    "information": Severity.INFO,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."
_CDATA_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "inform": Severity.INFO,
    "information": Severity.INFO,
    "info": Severity.INFO,
}

# Config noise error IDs to filter out — these are not real findings
_NOISE_IDS: set[str] = {
    "templateRecursion",
    "missingInclude",
    "missingIncludeSystem",
    "checkersReport",
    "toomanyconfigs",
    "purgedConfiguration",
    "ConfigurationNotChecked",
    "noValidConfiguration",
}


def _parse_cwe_attr(value: str | None) -> int | None:
    """Return a positive CWE id from cppcheck's ``cwe=`` attribute, else None."""
    if not value:
        return None
    try:
        cwe = int(value.strip())
    except ValueError:
        return None
    return cwe if cwe > 0 else None


def _int_attr(value: str | None) -> int | None:
    """Return an integer XML attribute value, or None when absent or not a number."""
    if not value:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _location_file(loc: Element) -> str:
    """The location's file with ``./`` stripped; ``""`` for none or the ``*`` wildcard."""
    file_path = loc.get("file", "")
    if file_path == "*":
        return ""
    if file_path.startswith("./"):
        file_path = file_path[2:]
    return file_path


def _location_column(loc: Element) -> int | None:
    """cppcheck columns are 1-based; ``column="0"`` means the column is unknown."""
    column = _int_attr(loc.get("column"))
    return column if column is not None and column > 0 else None


class CppcheckIngestor(BaseIngestor):
    """Parses cppcheck XML output files."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a cppcheck XML report."""
        if not path.exists():
            return False
        try:
            root = parse_xml_file(path, fmt="cppcheck")
        except IngestorError:
            return False
        if root.tag != "results":
            return False
        return root.find("cppcheck") is not None

    def extract_scanner_version(self, raw: bytes) -> str | None:
        """Return the version from ``<results><cppcheck version="..."/>``."""
        try:
            root = parse_xml_bytes(raw, fmt="cppcheck")
        except IngestorError:
            return None
        el = root.find("cppcheck")
        v = el.get("version") if el is not None else None
        return str(v) if v else None

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a cppcheck XML file and return a list of Finding objects."""
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        root = parse_xml_file(path, fmt="cppcheck")

        errors_el = root.find("errors")
        if errors_el is None:
            return []

        findings: list[Finding] = []
        registry = default_registry()

        # One finding per <error>. cppcheck lists the primary location first
        # ("The primary location is listed first", cppcheck manual; toXML
        # writes the call stack in reverse). Only that location is a ref.
        for error in errors_el.findall("error"):
            error_id = error.get("id", "")
            if error_id in _NOISE_IDS:
                continue
            severity = _SEVERITY_MAP.get(error.get("severity", "style"), Severity.LOW)

            locations = error.findall("location")
            source_refs: list[SourceCodeRef] = []
            hosts: list[str] = []
            if locations:
                primary = locations[0]
                primary_file = _location_file(primary)
                if primary_file:
                    hosts.append(primary_file)
                    source_refs.append(
                        SourceCodeRef(
                            file_path=primary_file,
                            start_line=_int_attr(primary.get("line")),
                            column=_location_column(primary),
                        )
                    )

            # The other locations (value-flow conditions, call sites) keep their
            # info text here; they are never is_sink=False refs.
            other_locations: list[dict[str, object]] = []
            for loc in locations[1:]:
                loc_file = _location_file(loc)
                if not loc_file:
                    continue
                other_locations.append(
                    {
                        "file": loc_file,
                        "line": _int_attr(loc.get("line")),
                        "column": _location_column(loc),
                        "info": loc.get("info"),
                    }
                )

            # CData enrichment
            cwe_id: int | None = None
            extra_fields: dict[str, object] = {}
            cdata_match = registry.lookup("cppcheck", error_id)
            if cdata_match is not None:
                cwe_id = cdata_match.cwe
                if cdata_match.confidence:
                    extra_fields["cdata_confidence"] = cdata_match.confidence
                if cdata_match.severity:
                    mapped = _CDATA_SEVERITY_MAP.get(cdata_match.severity.strip().lower())
                    if mapped is not None:
                        severity = mapped
                        extra_fields["cdata_severity_fallback"] = mapped.value.lower()
            if cwe_id is None:
                # Fall back to cppcheck's own cwe= attribute (e.g.
                # bufferAccessOutOfBounds -> 788) when CData has no mapping.
                cwe_id = _parse_cwe_attr(error.get("cwe"))
            if other_locations:
                extra_fields["cppcheck_locations"] = other_locations

            findings.append(
                Finding(
                    # One id per rule, as for SARIF: the location must not be in
                    # it, or every line shift would create a new rule key downstream.
                    id=f"cppcheck-{slugify(error_id)}",
                    title=error_id,
                    severity=severity,
                    description=error.get("msg", ""),
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    affected_hosts=hosts,
                    source_code_refs=source_refs,
                    source_tool="cppcheck",
                    raw_ref=error_id,
                    cwe_id=cwe_id,
                    extra_fields=extra_fields,
                )
            )

        return findings
