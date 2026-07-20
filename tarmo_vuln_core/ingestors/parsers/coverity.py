"""Coverity JSON ingestor."""

from __future__ import annotations

import json
from collections.abc import Mapping
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


def _as_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def _as_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value
    return default


def _as_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _primary_event_description(events: object) -> str | None:
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if event.get("remediation"):
            continue
        description = event.get("eventDescription") or event.get("covLStrEventDescription")
        if isinstance(description, str) and description.strip():
            return description.strip()
    return None


class CoverityIngestor(BaseIngestor):
    """Parses Coverity JSON output files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "issues" not in data:
                return False
            issues = data["issues"]
            if not isinstance(issues, list) or len(issues) == 0:
                return False
            return "checkerName" in issues[0]
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Coverity JSON: {e}") from e

        findings: list[Finding] = []

        for issue in data.get("issues", []):
            if not isinstance(issue, Mapping):
                continue

            checker_name = issue.get("checkerName", "")
            props = _as_mapping(issue.get("checkerProperties"))
            impact_str = _as_str(props.get("impact"), "Medium")
            severity = _SEVERITY_MAP.get(impact_str, Severity.MEDIUM)

            cwe_id = _as_int(props.get("cweCategory"))

            file_path = _as_str(
                issue.get("strippedMainEventFilePathname") or issue.get("mainEventFilePathname", "")
            )
            line = _as_int(issue.get("mainEventLineNumber"))
            events = issue.get("events", [])
            description = (
                _as_str(props.get("subcategoryLongDescription"))
                or _as_str(props.get("subcategoryShortDescription"))
                or _primary_event_description(events)
                or checker_name
            )

            # Source code ref
            source_refs: list[SourceCodeRef] = []
            if file_path:
                source_refs.append(SourceCodeRef(file_path=file_path, start_line=line))

            # Event trace — if >10 events, keep first 5 + last 5
            extra_fields: dict[str, object] = {}
            if events:
                event_trace = events[:5] + events[-5:] if len(events) > 10 else events
                extra_fields["event_trace"] = event_trace

            file_base = basename(file_path) if file_path else "unknown"
            finding_id = f"coverity-{slugify(checker_name)}-{slugify(file_base)}-l{line}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=checker_name,
                    severity=severity,
                    description=description,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="coverity",
                    raw_ref=checker_name,
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[file_path] if file_path else [],
                    extra_fields=extra_fields,
                )
            )

        return findings
