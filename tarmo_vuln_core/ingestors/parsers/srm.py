"""SRM XML ingestor with cross-scanner deduplication."""

from __future__ import annotations

from pathlib import Path

from tarmo_vuln_core.cdata import default_registry
from tarmo_vuln_core.ingestors._xml import parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Info": Severity.INFO,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


class SrmIngestor(BaseIngestor):
    """Parses SRM XML report files with cross-scanner deduplication."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            root = parse_xml_file(path, fmt="SRM")
        except IngestorError:
            return False
        if root.tag != "report":
            return False
        return root.find("findings") is not None

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        root = parse_xml_file(path, fmt="SRM")
        findings_el = root.find("findings")
        if findings_el is None:
            return []

        findings: list[Finding] = []
        registry = default_registry()
        # Track type+file+line -> first finding ID for cross-scanner dedup
        seen: dict[tuple[str, str, str], str] = {}

        for finding_el in findings_el.findall("finding"):
            finding_type = finding_el.get("type", "")
            sev_str = finding_el.get("severity", "Medium")
            cwe_str = finding_el.get("cwe", "")

            severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            cwe_id = int(cwe_str) if cwe_str.isdigit() else None

            tool_el = finding_el.find("tool")
            tool_name = tool_el.get("name", "") if tool_el is not None else ""

            file_el = finding_el.find("file")
            file_path = file_el.get("path", "") if file_el is not None else ""
            line_str = file_el.get("line", "") if file_el is not None else ""
            line = int(line_str) if line_str.isdigit() else None

            desc_el = finding_el.find("description")
            description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(SourceCodeRef(file_path=file_path, start_line=line))

            finding_id = (
                f"srm-{slugify(finding_type)}-{slugify(tool_name)}-{slugify(file_path)}-l{line}"
            )

            extra_fields: dict[str, object] = {}
            if cwe_id is None and finding_type:
                cdata_match = registry.lookup("srm", finding_type)
                if cdata_match is not None:
                    cwe_id = cdata_match.cwe
                    if cdata_match.confidence:
                        extra_fields["cdata_confidence"] = cdata_match.confidence

            # Cross-scanner dedup: if same type+file+line from different tool, mark as duplicate
            dedup_key = (finding_type, file_path, str(line))
            if dedup_key in seen:
                extra_fields["duplicate_of"] = seen[dedup_key]
            else:
                seen[dedup_key] = finding_id

            findings.append(
                Finding(
                    id=finding_id,
                    title=finding_type,
                    severity=severity,
                    description=description,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool=tool_name or "srm",
                    raw_ref=finding_el.get("id", ""),
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields=extra_fields,
                )
            )

        return findings
