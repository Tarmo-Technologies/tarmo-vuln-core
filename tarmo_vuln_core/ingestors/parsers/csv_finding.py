"""Generic CSV vulnerability import ingestor for pentest-scribe."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity
from tarmo_vuln_core.utils import slugify as _slugify_base

logger = logging.getLogger(__name__)

# Columns that must be present in the header row for auto-detection
_REQUIRED_COLUMNS = {"title", "severity"}

# All supported column names (others are ignored)
_KNOWN_COLUMNS = {
    "id",
    "title",
    "severity",
    "affected_hosts",
    "description",
    "impact",
    "remediation",
    "cvss_score",
    "cvss_vector",
    "cvss_version",
    "cwe_id",
    "owasp_id",
    "raw_ref",
    "notes",
    "compliance_refs",
    "steps",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}


def _slugify(text: str) -> str:
    """Convert a title string to a URL-safe slug for use as a finding id."""
    return _slugify_base(text)[:80]


def _parse_list(value: str) -> list[str]:
    """Split a semicolon- or comma-delimited string into a stripped list."""
    if not value:
        return []
    delimiter = ";" if ";" in value else ","
    return [item.strip() for item in value.split(delimiter) if item.strip()]


class CsvFindingIngestor(BaseIngestor):
    """Ingestor for generic CSV vulnerability spreadsheets.

    Expected header columns (case-insensitive):
      Required: ``title``, ``severity``
      Optional: ``id``, ``affected_hosts``, ``description``, ``impact``,
                ``remediation``, ``cvss_score``, ``cvss_vector``,
                ``cvss_version``, ``cwe_id``, ``owasp_id``, ``raw_ref``,
                ``notes``, ``compliance_refs``, ``steps``

    Multi-value columns (``affected_hosts``, ``compliance_refs``, ``steps``)
    accept comma- or semicolon-delimited values within a single cell.
    """

    category = FindingCategory.MANUAL

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".csv"]

    def can_handle(self, path: Path) -> bool:
        """Return True for ``.csv`` files whose header contains required columns."""
        if path.suffix.lower() != ".csv":
            return False
        try:
            with path.open(newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                header_row = next(reader, None)
            if header_row is None:
                return False
            header = {col.strip().lower() for col in header_row}
            return _REQUIRED_COLUMNS.issubset(header)
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a CSV file and return normalized Finding objects.

        Args:
            path: Path to the CSV file.

        Returns:
            List of Finding objects.

        Raises:
            IngestorError: If the file cannot be read or is missing required columns.
        """
        try:
            with path.open(newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames is None:
                    raise IngestorError(f"CSV file has no header row: {path}")
                # Normalize header keys to lowercase
                rows = [
                    {k.strip().lower(): (v or "").strip() for k, v in row.items()} for row in reader
                ]
        except OSError as exc:
            raise IngestorError(f"Cannot read CSV file {path}: {exc}") from exc

        if not rows:
            logger.warning("CSV file contains no data rows: %s", path)
            return []

        # Validate required columns
        header = set(rows[0].keys())
        missing = _REQUIRED_COLUMNS - header
        if missing:
            raise IngestorError(
                f"CSV file {path} is missing required columns: {', '.join(sorted(missing))}"
            )

        findings: list[Finding] = []
        seen_ids: set[str] = set()

        for row_num, row in enumerate(rows, start=2):  # 2 = first data row
            title = row.get("title", "").strip()
            if not title:
                logger.warning("Row %d: empty title — skipping", row_num)
                continue

            severity_raw = row.get("severity", "").strip().lower()
            severity = _SEVERITY_MAP.get(severity_raw)
            if severity is None:
                logger.warning(
                    "Row %d: unknown severity %r — defaulting to INFO", row_num, severity_raw
                )
                severity = Severity.INFO

            # Build a unique id
            finding_id = row.get("id", "").strip() or _slugify(title)
            # Deduplicate within the same file
            if finding_id in seen_ids:
                finding_id = f"{finding_id}-{row_num}"
            seen_ids.add(finding_id)

            affected_hosts = _parse_list(row.get("affected_hosts", ""))
            description = row.get("description", "") or "See CSV import."
            impact = row.get("impact", "") or "See CSV import."
            remediation = row.get("remediation", "") or "See CSV import."
            notes = row.get("notes", "")
            raw_ref = row.get("raw_ref", "") or None
            owasp_id = row.get("owasp_id", "") or None

            cvss_score: float | None = None
            raw_cvss = row.get("cvss_score", "").strip()
            if raw_cvss:
                try:
                    cvss_score = float(raw_cvss)
                except ValueError:
                    logger.warning("Row %d: invalid cvss_score %r — ignoring", row_num, raw_cvss)

            cwe_id: int | None = None
            raw_cwe = row.get("cwe_id", "").strip()
            if raw_cwe:
                try:
                    cwe_id = int(raw_cwe)
                except ValueError:
                    logger.warning("Row %d: invalid cwe_id %r — ignoring", row_num, raw_cwe)

            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=severity,
                    affected_hosts=affected_hosts,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    cvss_score=cvss_score,
                    cvss_vector=row.get("cvss_vector", "") or None,
                    cvss_version=row.get("cvss_version", "") or None,
                    cwe_id=cwe_id,
                    owasp_id=owasp_id,
                    raw_ref=raw_ref,
                    notes=notes,
                    compliance_refs=_parse_list(row.get("compliance_refs", "")),
                    steps=_parse_list(row.get("steps", "")),
                    source_tool="csv",
                )
            )

        return findings
