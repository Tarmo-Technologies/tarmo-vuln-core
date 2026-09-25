"""cppcheck XML ingestor."""

from __future__ import annotations

from pathlib import Path

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

        # Group by (error_id, msg) to deduplicate
        groups: dict[tuple[str, str], dict] = {}

        errors_el = root.find("errors")
        if errors_el is None:
            return []

        for error in errors_el.findall("error"):
            error_id = error.get("id", "")
            if error_id in _NOISE_IDS:
                continue
            msg = error.get("msg", "")
            sev_str = error.get("severity", "style")
            key = (error_id, msg)

            if key not in groups:
                groups[key] = {
                    "id": error_id,
                    "msg": msg,
                    "severity": sev_str,
                    "files": [],
                    "source_code_refs": [],
                    "tool_cwe": None,
                }
            if groups[key]["tool_cwe"] is None:
                groups[key]["tool_cwe"] = _parse_cwe_attr(error.get("cwe"))

            for loc in error.findall("location"):
                file_path = loc.get("file", "")
                # Skip star wildcard locations
                if file_path == "*":
                    continue
                # Strip leading ./
                if file_path.startswith("./"):
                    file_path = file_path[2:]
                if file_path and file_path not in groups[key]["files"]:
                    groups[key]["files"].append(file_path)
                if file_path:
                    line_str = loc.get("line")
                    line_num = int(line_str) if line_str else None
                    groups[key]["source_code_refs"].append(
                        SourceCodeRef(file_path=file_path, start_line=line_num)
                    )

        findings: list[Finding] = []
        registry = default_registry()

        for (_error_id, _msg), group in groups.items():
            severity = _SEVERITY_MAP.get(group["severity"], Severity.LOW)

            # CData enrichment
            cwe_id: int | None = None
            extra_fields: dict[str, object] = {}
            cdata_match = registry.lookup("cppcheck", group["id"])
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
                cwe_id = group["tool_cwe"]

            findings.append(
                Finding(
                    id=f"cppcheck-{slugify(group['id'])}",
                    title=group["id"],
                    severity=severity,
                    description=group["msg"],
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    affected_hosts=group["files"],
                    source_code_refs=group["source_code_refs"],
                    source_tool="cppcheck",
                    raw_ref=group["id"],
                    cwe_id=cwe_id,
                    extra_fields=extra_fields,
                )
            )

        return findings
