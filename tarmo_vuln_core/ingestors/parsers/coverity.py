"""Coverity JSON ingestor."""

from __future__ import annotations

import json
from collections.abc import Mapping
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
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


def _derive_strip_prefix(unstripped: str, stripped: str) -> str | None:
    """Recover the ``cov-format-errors --strip-path`` prefix from one path pair.

    ``/home/ci/work/build/gen/foo_idl.c`` + ``build/gen/foo_idl.c`` ->
    ``/home/ci/work/``. None when nothing was stripped or the pair disagrees.
    """
    if not unstripped or not stripped or unstripped == stripped or stripped.startswith("/"):
        return None
    if unstripped.endswith("/" + stripped):
        return unstripped[: -len(stripped)]
    return None


def _event_file_path(event: Mapping[str, object], strip_prefix: str | None) -> str | None:
    stripped = _as_str(event.get("strippedFilePathname"))
    if stripped:
        return stripped
    raw = _as_str(event.get("filePathname"))
    if raw and strip_prefix and raw.startswith(strip_prefix):
        return raw[len(strip_prefix) :]
    return raw or None


def _normalize_events(events: list[object], strip_prefix: str | None) -> list[object]:
    """Copy *events*, adding a normalized ``file_path`` to each (nested included).

    Uses the event's ``strippedFilePathname`` when present, otherwise applies the
    issue's derived strip prefix to ``filePathname``. Raw fields are untouched.
    """
    out: list[object] = []
    for event in events:
        if not isinstance(event, Mapping):
            out.append(event)
            continue
        copy = dict(event)
        path = _event_file_path(event, strip_prefix)
        if path:
            copy["file_path"] = path
        nested = event.get("events")
        if isinstance(nested, list):
            copy["events"] = _normalize_events(nested, strip_prefix)
        out.append(copy)
    return out


class CoverityIngestor(BaseIngestor):
    """Parses Coverity JSON output files."""

    category = FindingCategory.SAST

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

            main_path = _as_str(issue.get("mainEventFilePathname"))
            file_path = _as_str(issue.get("strippedMainEventFilePathname")) or main_path
            strip_prefix = _derive_strip_prefix(main_path, file_path)
            symbol = _as_str(issue.get("functionDisplayName")) or None
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
                source_refs.append(
                    SourceCodeRef(file_path=file_path, start_line=line, symbol=symbol)
                )

            # Event trace — if >10 events, keep first 5 + last 5
            extra_fields: dict[str, object] = {}
            if isinstance(events, list) and events:
                event_trace = events[:5] + events[-5:] if len(events) > 10 else events
                extra_fields["event_trace"] = _normalize_events(event_trace, strip_prefix)
            if main_path and main_path != file_path:
                extra_fields["resolved_path"] = main_path
            if strip_prefix:
                extra_fields["strip_prefix"] = strip_prefix

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
