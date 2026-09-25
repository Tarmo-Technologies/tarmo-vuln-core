"""Sigasi JSON diagnostic ingestor."""

from __future__ import annotations

import json
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.cdata import default_registry
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


class SigasiIngestor(BaseIngestor):
    """Parses Sigasi JSON diagnostic output files."""

    category = FindingCategory.SAST

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
            return isinstance(first, dict) and "code" in first and "language" in first
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Sigasi JSON: {e}") from e

        findings: list[Finding] = []
        registry = default_registry()

        for item in data:
            code = item.get("code", "")
            sev_str = item.get("severity", "INFO")
            message = item.get("message", "")
            file_path = item.get("file", "")
            line = item.get("line")
            language = item.get("language", "")

            severity = _SEVERITY_MAP.get(sev_str.upper(), Severity.INFO)

            # CData enrichment using compound key "{language}:{code}"
            cwe_id: int | None = None
            extra_fields: dict[str, object] = {}
            lookup_key = f"{language}:{code}"
            cdata_match = registry.lookup("sigasi", lookup_key)
            if cdata_match is not None:
                cwe_id = cdata_match.cwe
                if cdata_match.confidence:
                    extra_fields["cdata_confidence"] = cdata_match.confidence

            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(SourceCodeRef(file_path=file_path, start_line=line))

            file_base = basename(file_path) if file_path else "unknown"
            finding_id = f"sigasi-{code}-{slugify(file_base)}-l{line}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=f"{language}:{code}" if language else str(code),
                    severity=severity,
                    description=message,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="sigasi",
                    raw_ref=str(code),
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields=extra_fields,
                )
            )

        return findings
