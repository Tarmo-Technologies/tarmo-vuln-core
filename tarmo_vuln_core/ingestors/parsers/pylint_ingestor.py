"""PyLint JSON ingestor."""

from __future__ import annotations

import json
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.cdata import default_registry
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "convention": Severity.INFO,
    "refactor": Severity.INFO,
    "warning": Severity.LOW,
    "error": Severity.MEDIUM,
    "fatal": Severity.HIGH,
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


class PylintIngestor(BaseIngestor):
    """Parses PyLint JSON output files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list) or len(data) == 0:
                return False
            first = data[0]
            return isinstance(first, dict) and "message-id" in first and "symbol" in first
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse PyLint JSON: {e}") from e

        findings: list[Finding] = []
        registry = default_registry()

        for item in data:
            msg_type = item.get("type", "")
            message_id = item.get("message-id", "")
            symbol = item.get("symbol", "")
            message = item.get("message", "")
            line = item.get("line")
            file_path = item.get("path", "")

            severity = _SEVERITY_MAP.get(msg_type, Severity.INFO)

            # CData enrichment
            cwe_id: int | None = None
            extra_fields: dict[str, object] = {}
            if message_id:
                cdata_match = registry.lookup("pylint", message_id)
                if cdata_match is not None:
                    cwe_id = cdata_match.cwe
                    if cdata_match.confidence:
                        extra_fields["cdata_confidence"] = cdata_match.confidence
                    if cdata_match.severity:
                        mapped = _CDATA_SEVERITY_MAP.get(cdata_match.severity.strip().lower())
                        if mapped is not None:
                            severity = mapped
                            extra_fields["cdata_severity_fallback"] = mapped.value.lower()

            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(SourceCodeRef(file_path=file_path, start_line=line))

            file_base = basename(file_path) if file_path else "unknown"
            finding_id = f"pylint-{message_id}-{slugify(file_base)}-l{line}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=symbol,
                    severity=severity,
                    description=message,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="pylint",
                    raw_ref=message_id,
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields=extra_fields,
                )
            )

        return findings
