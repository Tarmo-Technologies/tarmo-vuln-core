"""Checkmarx SAST XML ingestor."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from tarmo_vuln_core.cdata import default_registry
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."

_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Information": Severity.INFO,
}


class CheckmarxIngestor(BaseIngestor):
    """Parses Checkmarx SAST XML output files (CxXMLResults)."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".xml"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            tree = ET.parse(path)  # noqa: S314
            return tree.getroot().tag == "CxXMLResults"
        except Exception:
            return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            root = ET.fromstring(raw)  # noqa: S314
        except ET.ParseError:
            return None
        v = root.attrib.get("CheckmarxVersion")
        return str(v) if v else None

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            tree = ET.parse(path)  # noqa: S314
        except ET.ParseError as e:
            raise IngestorError(f"Failed to parse Checkmarx XML: {e}") from e

        root = tree.getroot()
        findings: list[Finding] = []
        registry = default_registry()

        for query in root.findall("Query"):
            query_name = query.get("name", "")
            cwe_str = query.get("cweId", "")
            sev_str = query.get("Severity", "Medium")
            severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            cwe_id = int(cwe_str) if cwe_str.isdigit() else None

            # CData enrichment if CWE not in XML
            if cwe_id is None:
                match = registry.lookup("checkmarx", query_name)
                if match:
                    cwe_id = match.cwe

            for result in query.findall("Result"):
                file_name = result.get("FileName", "")
                line_str = result.get("Line", "")
                line_num = int(line_str) if line_str.isdigit() else None
                result_id = result.get("NodeId", "")

                # Build data flow trace + source/sink refs from PathNodes.
                data_flow: list[dict[str, object]] = []
                path_node_refs: list[SourceCodeRef] = []

                for path_el in result.findall(".//Path"):
                    for node in path_el.findall("PathNode"):
                        pn_file = ""
                        pn_line: int | None = None
                        pn_col: int | None = None
                        pn_name: str | None = None

                        fn_el = node.find("FileName")
                        if fn_el is not None and fn_el.text:
                            pn_file = fn_el.text
                        ln_el = node.find("Line")
                        if ln_el is not None and ln_el.text and ln_el.text.isdigit():
                            pn_line = int(ln_el.text)
                        col_el = node.find("Column")
                        if col_el is not None and col_el.text and col_el.text.isdigit():
                            pn_col = int(col_el.text)
                        name_el = node.find("Name")
                        if name_el is not None and name_el.text:
                            pn_name = name_el.text

                        data_flow.append(
                            {"file": pn_file, "line": pn_line, "snippet": pn_name or ""}
                        )
                        if pn_file:
                            path_node_refs.append(
                                SourceCodeRef(
                                    file_path=pn_file,
                                    start_line=pn_line,
                                    column=pn_col,
                                    symbol=pn_name,
                                    # Provisionally source — the last node is promoted
                                    # to is_sink=True after the loop.
                                    is_sink=False,
                                )
                            )

                # Promote the final PathNode to sink. Sink-only tools correlate
                # against this location; earlier nodes are taint sources.
                source_refs: list[SourceCodeRef] = []
                if path_node_refs:
                    last = path_node_refs[-1]
                    path_node_refs[-1] = last.model_copy(update={"is_sink": True})
                    source_refs = path_node_refs
                elif file_name:
                    # No PathNodes emitted — fall back to the Result-level location
                    # as the single sink ref.
                    source_refs.append(
                        SourceCodeRef(file_path=file_name, start_line=line_num, is_sink=True)
                    )

                extra_fields: dict[str, object] = {}
                if data_flow:
                    extra_fields["data_flow_trace"] = data_flow

                finding_id = f"checkmarx-{slugify(query_name)}-{slugify(file_name)}-l{line_num}"

                findings.append(
                    Finding(
                        id=finding_id,
                        title=query_name.replace("_", " "),
                        severity=severity,
                        description=f"{query_name} in {file_name}",
                        impact=_DEFAULT_IMPACT,
                        remediation=_DEFAULT_REMEDIATION,
                        source_tool="checkmarx",
                        raw_ref=result_id,
                        cwe_id=cwe_id,
                        source_code_refs=source_refs,
                        affected_hosts=[file_name] if file_name else [],
                        extra_fields=extra_fields,
                    )
                )

        return findings
