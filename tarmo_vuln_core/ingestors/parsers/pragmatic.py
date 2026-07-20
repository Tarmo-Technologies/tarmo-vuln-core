"""Pragmatic CSV ingestor (Ada-specific)."""

from __future__ import annotations

import csv
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


class PragmaticIngestor(BaseIngestor):
    """Parses Pragmatic CSV output files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".csv"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            text = path.read_text(encoding="utf-8")
            reader = csv.reader(text.splitlines())
            header = next(reader)
            header_lower = [h.strip().lower() for h in header]
            return (
                "checker" in header_lower and "filename" in header_lower and "cwe" in header_lower
            )
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8")
            reader = csv.DictReader(text.splitlines())
        except Exception as e:
            raise IngestorError(f"Failed to parse Pragmatic CSV: {e}") from e

        findings: list[Finding] = []

        for row in reader:
            checker = row.get("checker", "")
            file_path = row.get("filename", "")
            line_str = row.get("line", "")
            comments = row.get("comments", "")
            cwe_str = row.get("CWE", "")

            line = int(line_str) if line_str.isdigit() else None
            cwe_id = int(cwe_str) if cwe_str.isdigit() else None

            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(SourceCodeRef(file_path=file_path, start_line=line))

            file_base = basename(file_path) if file_path else "unknown"
            finding_id = f"pragmatic-{slugify(checker)}-{slugify(file_base)}-l{line}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=checker,
                    severity=Severity.MEDIUM,
                    description=comments,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="pragmatic",
                    raw_ref=checker,
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields={"language": "Ada"},
                )
            )

        return findings
