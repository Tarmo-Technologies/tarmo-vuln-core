"""SARP CSV ingestor."""

from __future__ import annotations

import csv
import warnings
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef

_SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Info": Severity.INFO,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."

_REQUIRED_COLUMNS = {"ID", "Path", "Type", "Scanner", "Tool Severity"}

_OPTIONAL_COLUMNS = (
    "Message",
    "Tool CWE",
    "Line",
    "Tool",
    "Confidence",
    "Exploit Maturity",
    "Proposed Mitigation",
    "Validator Justification",
    "Mitigation CVSS Vector",
    "Symbol",
    "Language",
    "Scoring Basis",
    # New combined-spreadsheet columns (issue #480):
    "CWE",
    "DestPath",
    "DestLine",
    "DestSymbol",
)


class SarpSchemaError(ValueError):
    """Raised when a SARP/combined CSV has structural problems.

    Attributes:
        missing_required: Required column names not present in the header.
        expected_required: Full list of required columns (for error rendering).
        expected_optional: Full list of accepted optional columns.
        unknown_columns: Columns in the header that are not part of the schema.
    """

    def __init__(
        self,
        *,
        missing_required: list[str],
        expected_required: list[str],
        expected_optional: list[str],
        unknown_columns: list[str],
    ) -> None:
        self.missing_required = missing_required
        self.expected_required = expected_required
        self.expected_optional = expected_optional
        self.unknown_columns = unknown_columns
        if missing_required:
            msg = (
                f"SARP/combined CSV is missing required column(s): "
                f"{', '.join(missing_required)}. "
                f"Required: {', '.join(expected_required)}."
            )
        else:
            msg = f"SARP/combined CSV header problem: unknown columns {unknown_columns}."
        super().__init__(msg)


class SarpIngestor(BaseIngestor):
    """Parses SARP CSV output files."""

    category = FindingCategory.SAST

    def __init__(self) -> None:
        # Reset on every ingest() call — reflects the most recent file.
        # Consumers that ingest multiple files must read this between calls.
        self.last_unknown_columns: list[str] = []

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
            header_set = {h.strip() for h in header}
            return _REQUIRED_COLUMNS.issubset(header_set)
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8")
            reader = csv.DictReader(text.splitlines())
        except Exception as e:
            raise IngestorError(f"Failed to parse SARP CSV: {e}") from e

        header = reader.fieldnames or []
        header_set = {h.strip() for h in header if h and h.strip()}
        known = set(_REQUIRED_COLUMNS) | set(_OPTIONAL_COLUMNS)
        unknown_cols = [h.strip() for h in header if h and h.strip() and h.strip() not in known]
        missing = [col for col in sorted(_REQUIRED_COLUMNS) if col not in header_set]
        if missing:
            # Report unknowns alongside missing so analysts see every schema
            # problem at once instead of fixing them in serial error rounds.
            raise SarpSchemaError(
                missing_required=missing,
                expected_required=sorted(_REQUIRED_COLUMNS),
                expected_optional=list(_OPTIONAL_COLUMNS),
                unknown_columns=unknown_cols,
            )

        self.last_unknown_columns = unknown_cols
        if unknown_cols:
            warnings.warn(
                f"SARP/combined CSV has unrecognized columns: {', '.join(unknown_cols)}",
                stacklevel=2,
            )

        findings: list[Finding] = []

        for row in reader:
            # Strip every cell on read. Analysts frequently deliver spreadsheets
            # with padded cells ("89 ", " 42 ", " Critical "); without stripping,
            # .isdigit() checks fail silently, _SEVERITY_MAP lookups miss, and
            # truthiness guards pass whitespace-only values through downstream.
            stripped = {k: (v or "").strip() for k, v in row.items() if k is not None}

            row_id = stripped.get("ID", "")
            finding_id = f"sarp-{row_id}"
            title = stripped.get("Type", "")
            message = stripped.get("Message", "")
            analyst_cwe_str = stripped.get("CWE", "")
            tool_cwe_str = stripped.get("Tool CWE", "")
            cwe_str = analyst_cwe_str if analyst_cwe_str else tool_cwe_str
            sev_str = stripped.get("Tool Severity", "") or "Medium"
            scanner = stripped.get("Scanner", "")
            file_path = stripped.get("Path", "")
            line_str = stripped.get("Line", "")
            tool = stripped.get("Tool", "")
            confidence = stripped.get("Confidence", "")
            exploit_maturity = stripped.get("Exploit Maturity", "")
            proposed_mitigation = stripped.get("Proposed Mitigation", "")
            validator_justification = stripped.get("Validator Justification", "")
            cvss_vector = stripped.get("Mitigation CVSS Vector", "")
            symbol = stripped.get("Symbol", "")
            language = stripped.get("Language", "")
            scoring_basis = stripped.get("Scoring Basis", "")

            severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            cwe_id = int(cwe_str) if cwe_str.isdigit() else None
            line = int(line_str) if line_str.isdigit() else None

            dest_path = stripped.get("DestPath", "")
            dest_line_str = stripped.get("DestLine", "")
            dest_symbol = stripped.get("DestSymbol", "")
            dest_line = int(dest_line_str) if dest_line_str.isdigit() else None
            has_dest = bool(dest_path or dest_line_str or dest_symbol)

            # Use proposed mitigation as remediation if available
            remediation = proposed_mitigation if proposed_mitigation else _DEFAULT_REMEDIATION

            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(
                    SourceCodeRef(
                        file_path=file_path,
                        start_line=line,
                        symbol=symbol or None,
                        is_sink=not has_dest,
                    )
                )
            if has_dest:
                sink_path = dest_path or file_path
                if sink_path:
                    source_refs.append(
                        SourceCodeRef(
                            file_path=sink_path,
                            start_line=dest_line,
                            symbol=dest_symbol or None,
                            is_sink=True,
                        )
                    )

            extra_fields: dict[str, object] = {}
            if analyst_cwe_str and tool_cwe_str:
                extra_fields["tool_cwe"] = tool_cwe_str
            if confidence:
                extra_fields["cdata_confidence"] = confidence
            if exploit_maturity:
                extra_fields["exploit_maturity"] = exploit_maturity
            if validator_justification:
                extra_fields["validator_justification"] = validator_justification
            if symbol:
                extra_fields["symbol"] = symbol
            if language:
                extra_fields["language"] = language
            if scoring_basis:
                extra_fields["scoring_basis"] = scoring_basis

            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=severity,
                    description=message,
                    impact=_DEFAULT_IMPACT,
                    remediation=remediation,
                    source_tool=scanner,
                    raw_ref=tool,
                    cwe_id=cwe_id,
                    cvss_vector=cvss_vector if cvss_vector else None,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields=extra_fields,
                )
            )

        return findings
