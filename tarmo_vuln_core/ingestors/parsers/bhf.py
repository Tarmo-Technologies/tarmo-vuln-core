"""BHF (Build Harness Fuzz) ingestors.

Two ingestors cover BHF's two output families:

* :class:`BhfIngestor` (``category = fuzz``) — ``bhf auto`` fuzz results. Accepts
  a work directory, its top-level ``findings.csv`` root-cause index, or a single
  ``findings/<id>/finding.json``. One :class:`Finding` is produced per root-cause
  row (BHF already clusters observations by ``cluster_key_full``); the
  representative ``finding.json`` supplies the rich evidence.
* :class:`BhfStaticIngestor` (``category = sast``) — ``bhf static`` results as
  ``static-report.sarif`` (a SARIF 2.1.0 run tagged ``bhfStaticSchemaVersion``)
  or the native ``static-report.json`` (``schema_version: bhf.static.v1``).

Path handling (air-gapped consumers must never see BHF host paths):

* Paths are rewritten POSIX-relative to the scanned source root: the
  ``source_root`` constructor argument, else ``auto/run.json`` → ``source_root``
  in the work directory. A ``/target/`` prefix (the VAMS container mount point)
  is stripped as well.
* Crash-stack frames outside the source root are *not* project frames and are
  dropped from :attr:`FuzzEvidence.stack`: the BHF runtime (``/opt/bhf``),
  generated harnesses (``.../harnesses/H-XXXX-XXXX/...``), libc (``csu/``,
  ``sysdeps/``), sanitizer interceptors (``__asan_*`` etc.) and frames with no
  file.
* When no source root is known, absolute paths that are not BHF runtime /
  harness / system paths are kept as-is (they cannot be proven foreign).

Field reference: BHF ``docs/finding-report-fields.md``.
"""

from __future__ import annotations

import csv
import json
import posixpath
import re
from pathlib import Path, PurePosixPath
from typing import Any

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.models import (
    Finding,
    FindingCategory,
    FuzzEvidence,
    Severity,
    SourceCodeRef,
    StackFrame,
)
from tarmo_vuln_core.utils import slugify

__all__ = ["BHF_CSV_HEADER_PREFIX", "BhfIngestor", "BhfStaticIngestor"]

#: Leading columns of a BHF ``findings.csv``. Matched exactly so generic CSV
#: ingestors never shadow BHF output and BHF never claims foreign CSVs.
BHF_CSV_HEADER_PREFIX: tuple[str, ...] = (
    "id",
    "count",
    "harness_id",
    "rule_id",
    "message",
    "exception_name",
    "sanitizer",
    "classification",
    "confirmation",
    "impact",
    "confidence",
    "verdict",
    "cwe",
)

#: BHF ``actionability.impact`` → Severity. ``unknown`` (undetermined) and any
#: unrecognized value map to MEDIUM: BHF only emits a finding after observing a
#: fault, so it is neither dismissed as LOW/INFO nor inflated to HIGH.
_IMPACT_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_IMPACT_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_UNKNOWN_SEVERITY = Severity.MEDIUM

_ENGINE = "bhf"
_SOURCE_TOOL = "bhf"
_TAG_PREFIX = "bhf"
_NON_DEFECT_CLASSIFICATIONS = frozenset({"intended_rejection"})

_MAX_PROBE_JSON_BYTES = 8 * 1024 * 1024
_MAX_HEADER_BYTES = 64 * 1024

_SANITIZER_FRAME_PREFIXES = (
    "__asan",
    "__ubsan",
    "__lsan",
    "__msan",
    "__tsan",
    "__sanitizer",
    "__interceptor",
)
_FOREIGN_ABS_PREFIXES = ("/opt/bhf/", "/usr/", "/lib/", "/lib64/")
_FOREIGN_REL_ROOTS = frozenset({"..", "csu", "sysdeps"})
_HARNESS_RE = re.compile(r"(?:^|/)harnesses/H-[0-9A-Za-z]+-[0-9A-Za-z]+(?:/|$)")
_TARGET_MOUNT = PurePosixPath("/target")
_EXCEPTION_PREFIXES = ("ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_", "ORACLE_")
_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)
_ASAN_ADDR_TAIL = re.compile(r"\s+on (?:unknown )?address 0x[0-9a-fA-F]+.*$")


# ── shared helpers ────────────────────────────────────────────────────────────


def _str(value: Any) -> str | None:
    """Return a stripped non-empty string, else None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _str(value)
    return int(text) if text is not None and text.isdigit() else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_cwes(value: Any) -> list[int]:
    """Parse ``"122;125"``, ``"CWE-120"`` or ``["CWE-122", "CWE-125"]`` into ints."""
    items: list[Any]
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = [p for p in re.split(r"[;,\s]+", value) if p]
    elif isinstance(value, int) and not isinstance(value, bool):
        items = [value]
    else:
        return []
    out: list[int] = []
    for item in items:
        m = _CWE_RE.fullmatch(str(item).strip())
        if m:
            cwe = int(m.group(1))
            if cwe not in out:
                out.append(cwe)
    return out


def _load_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestorError(f"Cannot read {what} '{path}': {exc}") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise IngestorError(f"Failed to parse {what} '{path}': {exc}") from exc


def _probe_json(path: Path) -> Any:
    """Parse a small JSON file for format sniffing; raise on anything unusual."""
    if path.stat().st_size > _MAX_PROBE_JSON_BYTES:
        raise ValueError("too large to probe")
    return json.loads(path.read_text(encoding="utf-8"))


class _PathMapper:
    """Rewrite tool-reported paths to POSIX paths relative to the scanned source root."""

    def __init__(self, source_root: PurePosixPath | None) -> None:
        self.root = source_root

    def project_path(self, raw: Any) -> str | None:
        """Return the project-relative path, or None if *raw* is not a project file."""
        text = _str(raw)
        if text is None:
            return None
        if text.startswith("file://"):
            text = text[len("file://") :]
        text = text.replace("\\", "/")
        if _HARNESS_RE.search(text):
            return None
        pure = PurePosixPath(posixpath.normpath(text))
        if pure.is_absolute():
            if self.root is not None and pure != self.root and pure.is_relative_to(self.root):
                return pure.relative_to(self.root).as_posix()
            if pure != _TARGET_MOUNT and pure.is_relative_to(_TARGET_MOUNT):
                return pure.relative_to(_TARGET_MOUNT).as_posix()
            if self.root is None and not text.startswith(_FOREIGN_ABS_PREFIXES):
                return pure.as_posix()
            return None
        if not pure.parts or pure.parts[0] in _FOREIGN_REL_ROOTS or str(pure) == ".":
            return None
        return pure.as_posix()

    def display_path(self, raw: Any) -> str | None:
        """Like :meth:`project_path` but keeps the original when it is not a project file."""
        mapped = self.project_path(raw)
        return mapped if mapped is not None else _str(raw)

    def scrub_text(self, text: str) -> str:
        """Strip the absolute source-root / ``/target`` prefixes from free text."""
        if self.root is not None and str(self.root) not in ("/", "."):
            text = text.replace(f"{self.root}/", "")
        return text.replace("/target/", "")

    def stack(self, frames: Any) -> list[StackFrame]:
        out: list[StackFrame] = []
        if not isinstance(frames, list):
            return out
        for frame in frames:
            if not isinstance(frame, dict):
                continue
            function = _str(frame.get("function"))
            if function is not None and function.startswith(_SANITIZER_FRAME_PREFIXES):
                continue
            file = self.project_path(frame.get("file"))
            if file is None:
                continue
            out.append(StackFrame(file=file, function=function, line=_int(frame.get("line"))))
        return out


def _bhf_tags(
    *, verdict: str | None, confidence: str | None, classification: str | None
) -> list[str]:
    tags: list[str] = []
    for key, value in (
        ("verdict", verdict),
        ("confidence", confidence),
        ("classification", classification),
    ):
        if value:
            tags.append(f"{_TAG_PREFIX}:{key}:{value}")
    return tags


def _humanize_exception(name: str) -> str:
    for prefix in _EXCEPTION_PREFIXES:
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix) :]
            break
    words = [w for w in name.split("_") if w]
    return " ".join(w if w.startswith("SIG") else w.capitalize() for w in words)


def _title(
    *,
    cwe_name: str | None,
    exception_name: str | None,
    function: str | None,
    message: str | None,
    rule_id: str | None,
) -> str:
    base = cwe_name or (_humanize_exception(exception_name) if exception_name else None)
    if base:
        return f"{base} in {function}" if function else base
    if message:
        cleaned = _ASAN_ADDR_TAIL.sub("", message.removeprefix("ERROR: ")).strip()
        return cleaned or message
    return f"BHF finding {rule_id}" if rule_id else "BHF finding"


# ── BhfIngestor (fuzz) ────────────────────────────────────────────────────────


def _read_csv_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        line = fh.readline(_MAX_HEADER_BYTES)
    return [h.strip() for h in next(csv.reader([line]), [])]


def _is_bhf_csv(path: Path) -> bool:
    if not path.is_file() or path.suffix.lower() != ".csv":
        return False
    header = _read_csv_header(path)
    return tuple(header[: len(BHF_CSV_HEADER_PREFIX)]) == BHF_CSV_HEADER_PREFIX


def _is_bhf_finding_doc(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("rule_id"), str)
        and isinstance(doc.get("actionability"), dict)
        and any(k in doc for k in ("signature", "cluster_key", "cluster_key_full"))
    )


def _csv_in_work_dir(work_dir: Path) -> Path | None:
    """Return the work dir's BHF findings.csv (or the ``auto/`` alias), if any."""
    for candidate in (work_dir / "findings.csv", work_dir / "auto" / "findings.csv"):
        if _is_bhf_csv(candidate):
            return candidate
    return None


def _work_dir_for_csv(csv_path: Path) -> Path:
    parent = csv_path.parent
    # ``auto/findings.csv`` is a compatibility alias of the top-level index.
    if (
        parent.name == "auto"
        and not (parent / "findings").is_dir()
        and (parent.parent / "findings").is_dir()
    ):
        return parent.parent
    return parent


class BhfIngestor(BaseIngestor):
    """Parses BHF (Build Harness Fuzz) ``bhf auto`` fuzz findings.

    Args:
        source_root: Absolute path of the scanned source tree as BHF saw it.
            Overrides ``auto/run.json``'s ``source_root``; used to rewrite
            paths relative to the project.

    ``ingest()`` accepts a work directory, its ``findings.csv`` (also the
    ``auto/findings.csv`` alias) or one ``finding.json``.
    """

    category = FindingCategory.FUZZ

    def __init__(self, source_root: Path | None = None) -> None:
        self._source_root = PurePosixPath(source_root.as_posix()) if source_root else None

    @property
    def supported_extensions(self) -> list[str]:
        return [".csv", ".json"]

    # -- detection ---------------------------------------------------------

    def can_handle(self, path: Path) -> bool:
        try:
            if path.is_dir():
                return _csv_in_work_dir(path) is not None or any(
                    (path / "findings").glob("*/finding.json")
                )
            if not path.is_file():
                return False
            suffix = path.suffix.lower()
            if suffix == ".csv":
                return _is_bhf_csv(path)
            if suffix == ".json":
                return _is_bhf_finding_doc(_probe_json(path))
        except (OSError, ValueError, UnicodeDecodeError, csv.Error):
            return False
        return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        """BHF version from a ``run.json`` payload; ``bhf auto`` does not record one yet."""
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(doc, dict):
            return None
        for key in ("bhf_version", "tool_version"):
            version = _str(doc.get(key))
            if version:
                return version
        return _str(_dict(doc.get("tool")).get("version"))

    # -- ingestion ---------------------------------------------------------

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"BHF input not found: {path}")
        if path.is_dir():
            csv_path = _csv_in_work_dir(path)
            if csv_path is not None:
                return self._ingest_csv(csv_path)
            return self._ingest_finding_dirs(path)
        if path.suffix.lower() == ".csv":
            if not _is_bhf_csv(path):
                raise IngestorError(
                    f"'{path.name}' is not a BHF findings.csv: header does not start with "
                    f"{','.join(BHF_CSV_HEADER_PREFIX)}"
                )
            return self._ingest_csv(path)
        if path.suffix.lower() == ".json":
            doc = _load_json(path, "BHF finding.json")
            if not _is_bhf_finding_doc(doc):
                raise IngestorError(
                    f"'{path.name}' is not a BHF finding.json "
                    "(needs rule_id, actionability and signature/cluster_key)"
                )
            finding_dir = path.parent
            work_dir = finding_dir.parent.parent if finding_dir.parent.name == "findings" else None
            mapper = _PathMapper(self._resolve_source_root(work_dir))
            return [_build_fuzz_finding(None, doc, finding_dir, work_dir, mapper)]
        raise IngestorError(
            f"'{path.name}' is not a BHF findings.csv, finding.json, or work directory"
        )

    def _resolve_source_root(self, work_dir: Path | None) -> PurePosixPath | None:
        if self._source_root is not None:
            return self._source_root
        if work_dir is None:
            return None
        run_json = work_dir / "auto" / "run.json"
        if not run_json.is_file():
            return None
        doc = _load_json(run_json, "BHF run.json")
        root = _str(_dict(doc).get("source_root"))
        return PurePosixPath(posixpath.normpath(root)) if root else None

    def _ingest_csv(self, csv_path: Path) -> list[Finding]:
        work_dir = _work_dir_for_csv(csv_path)
        mapper = _PathMapper(self._resolve_source_root(work_dir))
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise IngestorError(f"Failed to read BHF findings.csv '{csv_path}': {exc}") from exc

        findings: list[Finding] = []
        for index, row in enumerate(rows, start=2):
            bhf_id = _str(row.get("id"))
            if bhf_id is None:
                raise IngestorError(f"BHF findings.csv '{csv_path.name}' line {index}: empty id")
            finding_dir = work_dir / "findings" / bhf_id
            doc_path = finding_dir / "finding.json"
            doc = _load_json(doc_path, "BHF finding.json") if doc_path.is_file() else None
            findings.append(
                _build_fuzz_finding(
                    row, _dict(doc) if doc is not None else None, finding_dir, work_dir, mapper
                )
            )
        return findings

    def _ingest_finding_dirs(self, work_dir: Path) -> list[Finding]:
        doc_paths = sorted((work_dir / "findings").glob("*/finding.json"))
        if not doc_paths:
            raise IngestorError(
                f"'{work_dir}' is not a BHF work directory: "
                "no findings.csv or findings/*/finding.json"
            )
        mapper = _PathMapper(self._resolve_source_root(work_dir))

        groups: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
        for doc_path in doc_paths:
            doc = _load_json(doc_path, "BHF finding.json")
            if not _is_bhf_finding_doc(doc):
                raise IngestorError(f"'{doc_path}' is not a BHF finding.json")
            key = (
                _str(doc.get("cluster_key_full"))
                or _str(doc.get("signature"))
                or _str(doc.get("id"))
                or doc_path.parent.name
            )
            groups.setdefault(key, []).append((doc_path.parent, doc))

        findings: list[Finding] = []
        for members in groups.values():
            # Highest impact wins; ties keep the first (lowest id) member.
            rep_dir, rep_doc = max(
                members,
                key=lambda m: _IMPACT_RANK.get(
                    (_str(_dict(m[1].get("actionability")).get("impact")) or "").lower(), 0
                ),
            )
            member_ids = [_str(doc.get("id")) or d.name for d, doc in members if d is not rep_dir]
            findings.append(
                _build_fuzz_finding(None, rep_doc, rep_dir, work_dir, mapper, member_ids=member_ids)
            )
        return findings


def _build_fuzz_finding(
    row: dict[str, Any] | None,
    doc: dict[str, Any] | None,
    finding_dir: Path,
    work_dir: Path | None,
    mapper: _PathMapper,
    *,
    member_ids: list[str] | None = None,
) -> Finding:
    """Map one BHF root-cause row (CSV) and/or representative finding.json to a Finding.

    Group-level fields (impact, confidence, verdict, CWE union, strongest
    confirmation) come from the CSV row when present — BHF computes them over
    the whole cluster. Rich per-observation evidence comes from finding.json.
    """
    r = row or {}
    d = doc or {}
    act = _dict(d.get("actionability"))
    exc = _dict(d.get("exception"))
    target = _dict(d.get("target"))

    bhf_id = _str(r.get("id")) or _str(d.get("id")) or finding_dir.name
    impact = (
        _str(r.get("impact")) or _str(act.get("impact")) or _str(d.get("severity")) or ""
    ).lower()
    severity = _IMPACT_SEVERITY.get(impact, _UNKNOWN_SEVERITY)
    cwe_ids = _parse_cwes(r.get("cwe")) or _parse_cwes(act.get("cwe"))

    rule_id = _str(r.get("rule_id")) or _str(d.get("rule_id"))
    exception_name = _str(r.get("exception_name")) or _str(exc.get("name"))
    sanitizer = _str(r.get("sanitizer")) or _str(exc.get("sanitizer"))
    classification = _str(r.get("classification")) or _str(d.get("classification"))
    confirmation = _str(r.get("confirmation")) or _str(d.get("confirmation"))
    confidence = _str(r.get("confidence")) or _str(act.get("confidence"))
    verdict = _str(r.get("verdict")) or _str(act.get("verdict"))
    message = (
        _str(r.get("message"))
        or _str(exc.get("message"))
        or _str(_dict(d.get("oracle")).get("message"))
    )

    # Sink: actionability.sink → CSV sink columns → capability target.
    sink = _dict(act.get("sink"))
    sink_file_raw = (
        _str(sink.get("file")) or _str(r.get("sink_file")) or _str(target.get("source_path"))
    )
    sink_line = _int(sink.get("line")) or _int(r.get("sink_line")) or _int(target.get("line"))
    sink_func = (
        _str(sink.get("function"))
        or _str(r.get("sink_function"))
        or _str(r.get("entity"))
        or _str(target.get("name"))
    )

    refs: list[SourceCodeRef] = []
    sink_file = mapper.project_path(sink_file_raw)
    if sink_file is not None:
        refs.append(
            SourceCodeRef(file_path=sink_file, start_line=sink_line, symbol=sink_func, is_sink=True)
        )
    fix = _dict(act.get("fix_location"))
    if _str(fix.get("reason")) != "sink_frame_no_source":
        fix_file = mapper.project_path(fix.get("path"))
        fix_line = _int(fix.get("line"))
        if fix_file is not None and (fix_file, fix_line) != (sink_file, sink_line):
            refs.append(SourceCodeRef(file_path=fix_file, start_line=fix_line, is_sink=False))

    title = _title(
        cwe_name=_str(act.get("cwe_name")),
        exception_name=exception_name,
        function=sink_func,
        message=message,
        rule_id=rule_id,
    )

    explanation = _str(act.get("explanation"))
    desc_parts: list[str] = []
    if explanation:
        desc_parts.append(explanation)
    if message:
        if not explanation:
            desc_parts.append(message)
        elif sanitizer:
            desc_parts.append(f"Sanitizer report ({sanitizer}): {message}")
        else:
            desc_parts.append(f"Detector message: {message}")
    description = mapper.scrub_text("\n\n".join(desc_parts))

    remediation_parts: list[str] = []
    hints = act.get("patch_hints")
    if isinstance(hints, list):
        for hint in hints:
            guidance = _str(_dict(hint).get("guidance"))
            if guidance and guidance not in remediation_parts:
                remediation_parts.append(guidance)
    csv_remediation = _str(r.get("remediation"))
    if csv_remediation and csv_remediation not in remediation_parts:
        remediation_parts.append(csv_remediation)
    remediation = mapper.scrub_text("\n\n".join(remediation_parts))

    prosthetics = act.get("prosthetics")
    prosthetics_used: bool | None = None
    if isinstance(prosthetics, dict) and isinstance(prosthetics.get("used"), bool):
        prosthetics_used = prosthetics["used"]

    tags = _bhf_tags(verdict=verdict, confidence=confidence, classification=classification)
    if impact == "info" or classification in _NON_DEFECT_CLASSIFICATIONS:
        tags.append(f"{_TAG_PREFIX}:non-defect")
    if prosthetics_used:
        tags.append(f"{_TAG_PREFIX}:prosthetics")

    testcase = finding_dir / "testcase.bin"
    reproducer_path: str | None = None
    if testcase.is_file():
        reproducer_path = (
            testcase.relative_to(work_dir).as_posix() if work_dir is not None else testcase.name
        )

    if member_ids is None:
        raw_members = str(r.get("member_finding_ids") or "").split(";")
        member_ids = [m for m in (_str(x) for x in raw_members) if m]

    fuzz = FuzzEvidence(
        engine=_ENGINE,
        finding_id=bhf_id,
        rule_id=rule_id,
        exception_name=exception_name,
        sanitizer=sanitizer,
        classification=classification,
        verdict=verdict,
        confidence=confidence,
        confirmation=confirmation,
        harness_id=_str(r.get("harness_id")) or _str(d.get("harness_id")),
        cluster_key=_str(d.get("cluster_key")),
        signature=_str(r.get("signature")) or _str(d.get("signature")),
        member_ids=member_ids,
        stack=mapper.stack(exc.get("stack")),
        reproducer_path=reproducer_path,
        replay_command=f"bhf replay --finding findings/{bhf_id}",
        prosthetics_used=prosthetics_used,
        cwe_ids=cwe_ids,
    )

    extra: dict[str, Any] = {
        "bhf_count": _int(r.get("count")),
        "bhf_input_reachability": _str(d.get("input_reachability")),
        "bhf_dialect": _str(d.get("dialect")),
        "bhf_cluster_key_full": _str(d.get("cluster_key_full")),
        "bhf_data_flow": mapper.scrub_text(_str(r.get("data_flow")) or "") or None,
    }

    return Finding(
        id=f"bhf-{bhf_id}",
        title=title,
        severity=severity,
        cwe_id=cwe_ids[0] if cwe_ids else None,
        category=FindingCategory.FUZZ,
        affected_hosts=[sink_file] if sink_file else [],
        source_code_refs=refs,
        fuzz=fuzz,
        description=description,
        remediation=remediation,
        source_tool=_SOURCE_TOOL,
        raw_ref=bhf_id,
        tags=tags,
        extra_fields={k: v for k, v in extra.items() if v is not None},
    )


# ── BhfStaticIngestor (SAST) ──────────────────────────────────────────────────

_STATIC_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.INFO,
}
_STATIC_SCHEMA_PREFIX = "bhf.static."


def _is_bhf_sarif(doc: Any) -> bool:
    if not (
        isinstance(doc, dict)
        and doc.get("version") == "2.1.0"
        and isinstance(doc.get("runs"), list)
    ):
        return False
    for run in doc["runs"]:
        run = _dict(run)
        if _str(_dict(run.get("properties")).get("bhfStaticSchemaVersion")):
            return True
        driver = _dict(_dict(run.get("tool")).get("driver"))
        if (_str(driver.get("name")) or "").lower() == "bhf":
            return True
    return False


def _is_bhf_static_json(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and (_str(doc.get("schema_version")) or "").startswith(_STATIC_SCHEMA_PREFIX)
        and isinstance(doc.get("findings"), list)
    )


def _static_common(
    *,
    fingerprint: str | None,
    rule_id: str | None,
    rule_slug: str | None,
    message: str | None,
    evidence: Any,
    remediation: str | None,
    cwe_raw: Any,
    verdict: str | None,
    confidence: str | None,
    baseline: str | None,
    triage: str | None,
    language: str | None,
    engine: str | None,
    reachability: str | None,
) -> dict[str, Any]:
    """Field updates shared by the SARIF and native-JSON static paths."""
    details: list[str] = []
    if isinstance(evidence, list):
        for item in evidence:
            detail = _str(_dict(item).get("detail"))
            if detail and detail not in details:
                details.append(detail)
    description = "\n\n".join([p for p in [message, *details] if p])

    tags = _bhf_tags(verdict=verdict, confidence=confidence, classification=None)
    if baseline:
        tags.append(f"{_TAG_PREFIX}:baseline:{baseline}")
    if triage:
        tags.append(f"{_TAG_PREFIX}:triage:{triage}")

    updates: dict[str, Any] = {
        "tags": tags,
        "raw_ref": fingerprint or rule_id,
        "source_tool": _SOURCE_TOOL,
        "source_tools": [_SOURCE_TOOL],
        "category": FindingCategory.SAST,
        "extra_fields": {
            k: v
            for k, v in {
                "bhf_rule_id": rule_id,
                "bhf_rule_slug": rule_slug,
                "bhf_language": language,
                "bhf_engine": engine,
                "bhf_reachability": reachability,
            }.items()
            if v
        },
    }
    if message:
        updates["title"] = message
    if description:
        updates["description"] = description
    if remediation:
        updates["remediation"] = remediation
    if fingerprint:
        updates["id"] = f"bhf-static-{slugify(fingerprint)}"
    cwes = _parse_cwes(cwe_raw)
    if cwes:
        updates["cwe_id"] = cwes[0]
    return updates


class BhfStaticIngestor(SarifIngestor):
    """Parses BHF static-analysis output (``static-report.sarif`` / ``static-report.json``).

    SARIF goes through the generic :class:`SarifIngestor` (so level/
    security-severity mapping matches every other SARIF tool) and is then
    enriched with BHF properties: enclosing function → ``symbol``, ``cwe``,
    verdict/confidence/baseline/triage tags and the fingerprint as ``raw_ref``.
    """

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".sarif", ".json"]

    def can_handle(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.suffix.lower() not in (".sarif", ".json"):
                return False
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return False
        return _is_bhf_sarif(doc) or _is_bhf_static_json(doc)

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(doc, dict):
            return None
        for run in doc.get("runs") or []:
            driver = _dict(_dict(_dict(run).get("tool")).get("driver"))
            version = _str(driver.get("version")) or _str(driver.get("semanticVersion"))
            if version:
                return version
        return _str(doc.get("bhf_version")) or _str(doc.get("tool_version"))

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        doc = _load_json(path, "BHF static report")
        if _is_bhf_static_json(doc):
            return self._ingest_native(doc)
        if not _is_bhf_sarif(doc):
            raise IngestorError(
                f"'{path.name}' is not a BHF static report "
                "(expected SARIF with bhfStaticSchemaVersion or bhf.static.* JSON)"
            )
        return super().ingest(path)

    def _customize_finding(self, finding: Finding, *, result: dict, rule: dict) -> Finding:
        props = _dict(result.get("properties"))
        analysis = _dict(props.get("analysis"))
        actionability = _dict(analysis.get("actionability"))
        fingerprint = _str(props.get("fingerprint")) or _str(
            _dict(result.get("partialFingerprints")).get("bhfStaticFingerprint")
        )
        symbol = _str(analysis.get("enclosing_function"))
        mapper = _PathMapper(None)
        refs = [
            ref.model_copy(
                update={
                    "file_path": mapper.display_path(ref.file_path) or ref.file_path,
                    "symbol": ref.symbol or symbol,
                    "is_sink": True,
                }
            )
            for ref in finding.source_code_refs
        ]
        updates = _static_common(
            fingerprint=fingerprint,
            rule_id=_str(result.get("ruleId")),
            rule_slug=_str(rule.get("name")),
            message=_str(_dict(result.get("message")).get("text")),
            evidence=props.get("evidence"),
            remediation=_str(props.get("remediation")),
            cwe_raw=props.get("cwe"),
            verdict=_str(actionability.get("verdict")),
            confidence=_str(actionability.get("confidence")) or _str(props.get("confidence")),
            baseline=_str(props.get("baselineStatus")),
            triage=_str(props.get("triageState")),
            language=_str(props.get("language")),
            engine=_str(analysis.get("engine")),
            reachability=_str(analysis.get("reachability")),
        )
        updates["source_code_refs"] = refs
        updates["affected_hosts"] = list(dict.fromkeys(r.file_path for r in refs))
        return finding.model_copy(update=updates)

    def _ingest_native(self, doc: dict[str, Any]) -> list[Finding]:
        mapper = _PathMapper(None)
        findings: list[Finding] = []
        for raw in doc["findings"]:
            item = _dict(raw)
            analysis = _dict(item.get("analysis"))
            actionability = _dict(analysis.get("actionability"))
            location = _dict(item.get("location"))
            file_path = mapper.display_path(location.get("path"))
            symbol = _str(analysis.get("enclosing_function"))
            refs = (
                [
                    SourceCodeRef(
                        file_path=file_path,
                        start_line=_int(location.get("line")),
                        column=_int(location.get("column")),
                        symbol=symbol,
                        is_sink=True,
                    )
                ]
                if file_path
                else []
            )
            rule_id = _str(item.get("rule_id"))
            severity = _STATIC_SEVERITY.get(
                (_str(item.get("severity")) or "").lower(), _UNKNOWN_SEVERITY
            )
            base = Finding(
                id=f"bhf-static-{slugify(_str(item.get('id')) or rule_id or 'finding')}",
                title=rule_id or "BHF static finding",
                severity=severity,
                source_code_refs=refs,
                affected_hosts=[file_path] if file_path else [],
                source_tool=_SOURCE_TOOL,
            )
            updates = _static_common(
                fingerprint=_str(item.get("fingerprint")),
                rule_id=rule_id,
                rule_slug=_str(item.get("rule_slug")),
                message=_str(item.get("message")),
                evidence=item.get("evidence"),
                remediation=_str(item.get("remediation")),
                cwe_raw=item.get("cwe"),
                verdict=_str(actionability.get("verdict")),
                confidence=_str(actionability.get("confidence")) or _str(item.get("confidence")),
                baseline=_str(item.get("baseline_status")),
                triage=_str(_dict(item.get("triage")).get("state")),
                language=_str(item.get("language")),
                engine=_str(analysis.get("engine")),
                reachability=_str(analysis.get("reachability")),
            )
            findings.append(base.model_copy(update=updates))
        return findings
