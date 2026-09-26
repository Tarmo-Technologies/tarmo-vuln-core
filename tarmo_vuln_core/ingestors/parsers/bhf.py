"""BHF (Build Harness Fuzz) ingestors.

Two ingestors cover BHF's two output families:

* :class:`BhfIngestor` — ``bhf auto`` results. Accepts a work directory, its
  top-level ``findings.csv`` root-cause index, or a single
  ``findings/<id>/finding.json`` (joined to its ``findings.csv`` row when the
  work directory has one, so every entry point yields the same Finding). One
  :class:`Finding` is produced per root-cause row (BHF already clusters
  observations by ``cluster_key_full``); the representative ``finding.json``
  supplies the rich evidence. Fuzz / runtime rows are ``category = fuzz`` with
  :class:`FuzzEvidence`; static-scan rows (``F-STATIC-*`` / ``F-RO-*``,
  ``classification = static_scan`` or ``confirmation = static``) are
  ``category = sast`` with no fuzz evidence.
* :class:`BhfStaticIngestor` (``category = sast``) — ``bhf static`` results as
  ``static-report.sarif`` (a SARIF 2.1.0 run tagged ``bhfStaticSchemaVersion``)
  or the native ``static-report.json`` (``schema_version: bhf.static.v1``).
  ``bhf report --sarif`` fuzz SARIF is *not* claimed.

Identity: ``Finding.id`` is derived from BHF's cross-run dedup key
(``cluster_key_full``, else ``signature``, else rule + sink location) — never
from the run-local ``F-NNNN`` ordinal — and sanitizer messages are stripped of
ASLR-volatile addresses before they reach the title or description, so the
same bug fingerprints identically across runs.

Input hardening: finding ids must be plain path components (they become paths
and shell words); finding dirs, ``finding.json`` and ``testcase.bin`` are never
followed through symlinks or outside the work directory; JSON is size-capped
and nesting-safe.

Path handling (air-gapped consumers must never see BHF host paths):

* Paths are rewritten POSIX-relative to the scanned source root: the
  ``source_root`` constructor argument, else ``auto/run.json`` → ``source_root``
  in the work directory, else a root inferred from an absolute ``finding.json``
  sink that ends with the CSV's root-relative ``sink_file``. Windows roots and
  paths (``C:\\proj``) are normalized the same way. A ``/target/`` prefix (the
  VAMS container mount point) is stripped when no source root is known.
* Crash-stack frames outside the source root are *not* project frames and are
  dropped from :attr:`FuzzEvidence.stack`: the BHF runtime (``/opt/bhf``, even
  with source root ``/``), generated harnesses (``.../harnesses/H-XXXX-XXXX/...``),
  libc (``csu/``, ``sysdeps/``, ``nptl/``, ``stdlib/`` ...), toolchain/system
  paths, sanitizer interceptors (``__asan_*`` etc.) and frames with no file.
* When no source root is known, absolute paths that are not BHF runtime /
  harness / system paths are kept as-is (they cannot be proven foreign).

Field reference: BHF ``docs/finding-report-fields.md``.
"""

from __future__ import annotations

import csv
import json
import posixpath
import re
import shlex
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
_STATIC_CLASSIFICATION = "static_scan"
_STATIC_CONFIRMATION = "static"

#: Format-sniffing cap for fuzz-side JSON (``finding.json`` is a few KiB).
_MAX_PROBE_JSON_BYTES = 8 * 1024 * 1024
#: Format-sniffing cap for static reports (SARIF grows with the scanned tree).
_MAX_STATIC_PROBE_BYTES = 64 * 1024 * 1024
#: Ingest-time cap per ``finding.json``; read once per root-cause row.
_MAX_FINDING_JSON_BYTES = 8 * 1024 * 1024
_MAX_RUN_JSON_BYTES = 64 * 1024 * 1024
_MAX_HEADER_BYTES = 64 * 1024

#: A BHF finding id (``F-0000-c0dca483``, ``F-CAP-0000``, ``F-STATIC-0000``,
#: ``F-RO-BHF-401-0A1B2C3D``). It is used as a path component and a shell word,
#: so separators, ``.``/``..``, whitespace and metacharacters are refused.
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

_SANITIZER_FRAME_PREFIXES = (
    "__asan",
    "__ubsan",
    "__lsan",
    "__msan",
    "__tsan",
    "__sanitizer",
    "__interceptor",
)
_BHF_RUNTIME = PurePosixPath("/opt/bhf")
_SYSTEM_ABS_PREFIXES = ("/usr/", "/lib/", "/lib64/")
_WINDOWS_SYSTEM_DIRS = frozenset({"windows", "program files", "program files (x86)", "programdata"})
_FOREIGN_REL_ROOTS = frozenset({"..", "csu", "sysdeps"})
#: Top-level glibc source dirs. With libc debuginfo installed, libc frames
#: symbolize tree-relative (``nptl/pthread_kill.c``, ``stdlib/abort.c``); BHF
#: builds project code with absolute paths, so these are never project frames.
_GLIBC_REL_ROOTS = frozenset(
    {
        "assert",
        "ctype",
        "debug",
        "dirent",
        "dlfcn",
        "elf",
        "gmon",
        "iconv",
        "inet",
        "io",
        "libio",
        "locale",
        "login",
        "malloc",
        "misc",
        "nptl",
        "nss",
        "posix",
        "resolv",
        "rt",
        "setjmp",
        "signal",
        "socket",
        "stdio-common",
        "stdlib",
        "string",
        "sunrpc",
        "termios",
        "time",
        "wcsmbs",
    }
)
_HARNESS_RE = re.compile(r"(?:^|/)harnesses/H-[0-9A-Za-z]+-[0-9A-Za-z]+(?:/|$)")
_TARGET_MOUNT = PurePosixPath("/target")
_FS_ROOT = PurePosixPath("/")
_DRIVE_RE = re.compile(r"^([A-Za-z]):(?=/|$)")
_DRIVE_PART_RE = re.compile(r"^[a-z]:$")
_FILE_URI_DRIVE_RE = re.compile(r"^/[A-Za-z]:[\\/]")
#: Only a path that starts a token is rewritten: ``/src/`` must not match inside
#: ``/usr/src/``, nor ``/target/`` inside a URL or ``/opt/target/``.
_PATH_BOUNDARY = r"(?<![\w./\\-])"
_TARGET_SCRUB_RE = re.compile(_PATH_BOUNDARY + r"/target/")
_EXCEPTION_PREFIXES = ("ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_", "ORACLE_")
_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)
_ASAN_ADDR_TAIL = re.compile(r"\s+on (?:unknown )?address 0x[0-9a-fA-F]+.*$")
#: ASLR / input-dependent parts of a sanitizer line (addresses, registers,
#: access size). Stripped so titles/descriptions fingerprint the same across runs.
_VOLATILE_MESSAGE_RES = (
    re.compile(r"\s+on (?:unknown )?address 0x[0-9a-fA-F]+"),
    re.compile(r"\s+at pc 0x[0-9a-fA-F]+(?:\s+bp 0x[0-9a-fA-F]+)?(?:\s+sp 0x[0-9a-fA-F]+)?"),
    re.compile(r"\s*\(pc 0x[0-9a-fA-F]+[^)]*\)"),
    re.compile(r"\s*\((?:READ|WRITE) of size \d+\)"),
)
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")


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


def _load_json(path: Path, what: str, *, max_bytes: int | None = None) -> Any:
    """Read and parse JSON, converting every failure into :class:`IngestorError`."""
    try:
        if max_bytes is not None:
            size = path.stat().st_size
            if size > max_bytes:
                raise IngestorError(
                    f"{what} '{path}' is {size} bytes, which exceeds the {max_bytes}-byte limit"
                )
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestorError(f"Cannot read {what} '{path}': {exc}") from exc
    except RecursionError as exc:
        raise IngestorError(f"Failed to parse {what} '{path}': JSON nesting is too deep") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise IngestorError(f"Failed to parse {what} '{path}': {exc}") from exc


def _probe_json(path: Path, max_bytes: int = _MAX_PROBE_JSON_BYTES) -> Any:
    """Parse a small JSON file for format sniffing; raise on anything unusual.

    May raise OSError, ValueError, UnicodeDecodeError or RecursionError; callers
    treat any of them as "not this format".
    """
    if path.stat().st_size > max_bytes:
        raise ValueError("too large to probe")
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_id(value: str, where: str) -> str:
    """Return *value* if it is a plain BHF finding id; else raise IngestorError."""
    if not _SAFE_ID_RE.fullmatch(value):
        raise IngestorError(
            f"{where}: unsafe BHF finding id {value!r} (expected letters, digits, "
            "'.', '_' or '-', starting with a letter or digit)"
        )
    return value


def _contained_file(path: Path, base: Path) -> bool:
    """True for a regular, non-symlink file whose real location is inside *base*."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        return path.resolve().is_relative_to(base.resolve())
    except (OSError, RuntimeError):
        return False


def _stable_message(message: str) -> str:
    """Strip ASLR/input-volatile addresses, registers and sizes from a detector line."""
    out = message
    for pattern in _VOLATILE_MESSAGE_RES:
        out = pattern.sub("", out)
    out = _HEX_RE.sub("<addr>", out)
    return re.sub(r"[ \t]+", " ", out).strip()


# ── path mapping ──────────────────────────────────────────────────────────────


def _normalize_path_text(raw: str) -> str:
    """POSIX-normalize a tool path; ``C:\\x`` → ``/c:/x`` so drive paths are absolute."""
    text = raw.strip()
    if text.startswith("file://"):
        text = text[len("file://") :]
        if _FILE_URI_DRIVE_RE.match(text):
            text = text[1:]
    text = text.replace("\\", "/")
    if text.startswith(("//?/", "//./")):  # Windows verbatim / device prefix
        text = text[4:]
    m = _DRIVE_RE.match(text)
    if m:
        text = f"/{m.group(1).lower()}:{text[2:]}"
    return posixpath.normpath(text) if text else ""


def _normalize_root(raw: str | None) -> PurePosixPath | None:
    """Normalize a source root (POSIX or Windows); None unless it is absolute."""
    text = _str(raw)
    if text is None:
        return None
    pure = PurePosixPath(_normalize_path_text(text))
    return pure if pure.is_absolute() else None


def _is_drive_path(pure: PurePosixPath) -> bool:
    return len(pure.parts) > 1 and bool(_DRIVE_PART_RE.match(pure.parts[1]))


def _is_system_path(pure: PurePosixPath) -> bool:
    if pure.as_posix().startswith(_SYSTEM_ABS_PREFIXES):
        return True
    return (
        _is_drive_path(pure)
        and len(pure.parts) > 2
        and (pure.parts[2].lower() in _WINDOWS_SYSTEM_DIRS)
    )


def _display_absolute(pure: PurePosixPath) -> str:
    if _is_drive_path(pure):
        return "/".join([pure.parts[1].upper(), *pure.parts[2:]])
    return pure.as_posix()


def _root_scrub_re(root: PurePosixPath | None) -> re.Pattern[str] | None:
    """Regex matching ``<root>/`` at a path boundary, in POSIX or Windows spelling."""
    if root is None:
        return None
    parts = list(root.parts[1:])
    if not parts:
        return None
    sep = r"[\\/]+"
    if _DRIVE_PART_RE.match(parts[0]):
        letter = parts[0][0]
        head = f"[{letter.upper()}{letter.lower()}]:"
        pattern = sep.join([head, *(re.escape(p) for p in parts[1:])]) + sep
    else:
        pattern = "/" + "/".join(re.escape(p) for p in parts) + "/"
    return re.compile(_PATH_BOUNDARY + pattern)


def _infer_root(abs_raw: Any, rel_raw: Any) -> PurePosixPath | None:
    """Infer the source root from an absolute path and its root-relative twin.

    ``/usr/src/app/parse.c`` + ``parse.c`` → ``/usr/src/app``. Used when neither
    the caller nor ``auto/run.json`` supplies a root (current BHF writes the CSV
    ``sink_file`` relative to the scanned tree).
    """
    abs_text, rel_text = _str(abs_raw), _str(rel_raw)
    if abs_text is None or rel_text is None:
        return None
    a = PurePosixPath(_normalize_path_text(abs_text))
    b = PurePosixPath(_normalize_path_text(rel_text))
    if not a.is_absolute() or b.is_absolute() or not b.parts or b.parts[0] in _FOREIGN_REL_ROOTS:
        return None
    n = len(b.parts)
    if len(a.parts) <= n + 1 or a.parts[-n:] != b.parts:
        return None
    return PurePosixPath(*a.parts[:-n])


class _PathMapper:
    """Rewrite tool-reported paths to POSIX paths relative to the scanned source root."""

    def __init__(self, source_root: PurePosixPath | None) -> None:
        self.root = source_root
        # "/" (e.g. an extracted firmware rootfs) relativizes everything but
        # proves nothing project-owned, so it keeps the no-root foreign filters.
        self._scoped_root = None if source_root in (None, _FS_ROOT) else source_root
        self._root_scrub = _root_scrub_re(self._scoped_root)

    def project_path(self, raw: Any, *, frame: bool = False) -> str | None:
        """Return the project-relative path, or None if *raw* is not a project file.

        ``frame=True`` additionally treats glibc tree-relative paths as foreign
        (only crash-stack frames carry those; sinks may legitimately be relative).
        """
        text = _str(raw)
        if text is None:
            return None
        norm = _normalize_path_text(text)
        if not norm or norm == "." or _HARNESS_RE.search(norm):
            return None
        pure = PurePosixPath(norm)
        if pure.is_absolute():
            return self._project_absolute(pure)
        if not pure.parts or pure.parts[0] in _FOREIGN_REL_ROOTS:
            return None
        if frame and pure.parts[0] in _GLIBC_REL_ROOTS:
            return None
        return pure.as_posix()

    def _project_absolute(self, pure: PurePosixPath) -> str | None:
        root = self._scoped_root
        if root is not None and pure != root and pure.is_relative_to(root):
            return pure.relative_to(root).as_posix()
        if pure.is_relative_to(_BHF_RUNTIME):
            return None
        if root is None and pure != _TARGET_MOUNT and pure.is_relative_to(_TARGET_MOUNT):
            return pure.relative_to(_TARGET_MOUNT).as_posix()
        if root is not None or _is_system_path(pure):
            return None
        if self.root == _FS_ROOT:
            return None if pure == _FS_ROOT else pure.relative_to(_FS_ROOT).as_posix()
        return _display_absolute(pure)

    def display_path(self, raw: Any) -> str | None:
        """Like :meth:`project_path` but keeps the original when it is not a project file."""
        mapped = self.project_path(raw)
        return mapped if mapped is not None else _str(raw)

    def scrub_text(self, text: str) -> str:
        """Strip the source-root (and, rootless, ``/target``) prefix from free text."""
        if self._root_scrub is not None:
            text = self._root_scrub.sub("", text)
        if self._scoped_root is None or self._scoped_root == _TARGET_MOUNT:
            text = _TARGET_SCRUB_RE.sub("", text)
        return text

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
            file = self.project_path(frame.get("file"), frame=True)
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
        cleaned = _stable_message(_ASAN_ADDR_TAIL.sub("", message.removeprefix("ERROR: ")))
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
        and (
            any(k in doc for k in ("signature", "cluster_key", "cluster_key_full"))
            # Static-scan sidecars (F-STATIC-* / F-RO-*) carry no cluster keys.
            or doc.get("classification") == _STATIC_CLASSIFICATION
            or doc.get("report_only") is True
        )
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


def _csv_member_ids(row: dict[str, Any]) -> list[str]:
    """``member_finding_ids`` as plain ids (junk entries are dropped, not trusted)."""
    raw = str(row.get("member_finding_ids") or "").split(";")
    return [m for m in (_str(x) for x in raw) if m and _SAFE_ID_RE.fullmatch(m)]


def _load_finding_doc(finding_dir: Path, work_dir: Path) -> dict[str, Any] | None:
    """Load ``finding_dir/finding.json`` unless it is symlinked or escapes the work dir."""
    doc_path = finding_dir / "finding.json"
    if finding_dir.is_symlink() or not _contained_file(doc_path, work_dir / "findings"):
        return None
    return _dict(_load_json(doc_path, "BHF finding.json", max_bytes=_MAX_FINDING_JSON_BYTES))


def _reproducer_path(finding_dir: Path, work_dir: Path | None) -> str | None:
    base = work_dir / "findings" if work_dir is not None else finding_dir
    testcase = finding_dir / "testcase.bin"
    if finding_dir.is_symlink() or not _contained_file(testcase, base):
        return None
    if work_dir is None:
        return testcase.name
    try:
        return testcase.relative_to(work_dir).as_posix()
    except ValueError:
        return None


def _member_ids_of(finding: Finding) -> list[str]:
    if finding.fuzz is not None:
        return list(finding.fuzz.member_ids)
    members = finding.extra_fields.get("bhf_member_ids")
    return list(members) if isinstance(members, list) else []


def _merge_same_id(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that resolved to the same stable id (first one wins)."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        keep = merged.get(finding.id)
        if keep is None:
            merged[finding.id] = finding
            continue
        extra = dict(keep.extra_fields)
        extra["bhf_count"] = int(extra.get("bhf_count") or 1) + int(
            finding.extra_fields.get("bhf_count") or 1
        )
        absorbed = [
            m for m in [finding.raw_ref, *_member_ids_of(finding)] if m and m != keep.raw_ref
        ]
        members = list(dict.fromkeys([*_member_ids_of(keep), *absorbed]))
        update: dict[str, Any] = {"extra_fields": extra}
        if keep.fuzz is not None:
            update["fuzz"] = keep.fuzz.model_copy(update={"member_ids": members})
        else:
            extra["bhf_member_ids"] = members
        merged[finding.id] = keep.model_copy(update=update)
    return list(merged.values())


#: Path keys the generic SARIF layer adds (see ``sarif._PROVENANCE_KEYS``).
_SARIF_PATH_KEYS = ("uri_base_id", "resolved_path", "artifact_roles", "generated_hint")


def _sarif_path_provenance(extra: dict[str, Any], refs: list[SourceCodeRef]) -> dict[str, Any]:
    """The SARIF path-provenance keys of *extra*, re-aligned to the display-mapped *refs*."""
    kept: dict[str, Any] = {k: extra[k] for k in _SARIF_PATH_KEYS if k in extra}
    entries = extra.get("path_provenance")
    if isinstance(entries, list):
        kept["path_provenance"] = [
            {**entry, "file_path": refs[i].file_path}
            if isinstance(entry, dict) and i < len(refs)
            else entry
            for i, entry in enumerate(entries)
        ]
    return kept


class BhfIngestor(BaseIngestor):
    """Parses BHF (Build Harness Fuzz) ``bhf auto`` findings.

    Args:
        source_root: Absolute path of the scanned source tree as BHF saw it
            (POSIX or Windows spelling). Overrides ``auto/run.json``'s
            ``source_root``; used to rewrite paths relative to the project.

    ``ingest()`` accepts a work directory, its ``findings.csv`` (also the
    ``auto/findings.csv`` alias) or one ``finding.json``.
    """

    category = FindingCategory.FUZZ

    def __init__(self, source_root: Path | None = None) -> None:
        self._source_root = _normalize_root(str(source_root)) if source_root is not None else None

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
        except (OSError, ValueError, UnicodeDecodeError, RecursionError, csv.Error):
            return False
        return False

    def extract_scanner_version(self, raw: bytes) -> str | None:
        """BHF version from a ``run.json`` payload; ``bhf auto`` does not record one yet."""
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
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
            return self._ingest_finding_json(path)
        raise IngestorError(
            f"'{path.name}' is not a BHF findings.csv, finding.json, or work directory"
        )

    def _ingest_finding_json(self, path: Path) -> list[Finding]:
        doc = _load_json(path, "BHF finding.json", max_bytes=_MAX_FINDING_JSON_BYTES)
        if not _is_bhf_finding_doc(doc):
            raise IngestorError(
                f"'{path.name}' is not a BHF finding.json "
                "(needs rule_id, actionability and signature/cluster_key)"
            )
        finding_dir = path.parent
        work_dir = finding_dir.parent.parent if finding_dir.parent.name == "findings" else None
        if work_dir is not None:
            # A recursive directory walk reaches both findings.csv and every
            # finding.json: join the CSV row so both entry points agree.
            csv_path = _csv_in_work_dir(work_dir)
            if csv_path is not None:
                doc_id = _safe_id(_str(doc.get("id")) or finding_dir.name, f"'{path}'")
                joined = self._ingest_csv(csv_path, only=doc_id)
                if joined:
                    return joined
        mapper = _PathMapper(self._resolve_source_root(work_dir))
        return [
            _build_fuzz_finding(
                None,
                doc,
                finding_dir,
                mapper,
                reproducer_path=_reproducer_path(finding_dir, work_dir),
            )
        ]

    def _resolve_source_root(self, work_dir: Path | None) -> PurePosixPath | None:
        if self._source_root is not None:
            return self._source_root
        if work_dir is None:
            return None
        run_json = work_dir / "auto" / "run.json"
        if run_json.is_symlink() or not run_json.is_file():
            return None
        doc = _load_json(run_json, "BHF run.json", max_bytes=_MAX_RUN_JSON_BYTES)
        return _normalize_root(_str(_dict(doc).get("source_root")))

    def _ingest_csv(self, csv_path: Path, *, only: str | None = None) -> list[Finding]:
        """Ingest a findings.csv; with *only*, just the row whose id/members include it."""
        work_dir = _work_dir_for_csv(csv_path)
        mapper = _PathMapper(self._resolve_source_root(work_dir))
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise IngestorError(f"Failed to read BHF findings.csv '{csv_path}': {exc}") from exc

        findings: list[Finding] = []
        seen: dict[str, int] = {}
        for index, row in enumerate(rows, start=2):
            where = f"BHF findings.csv '{csv_path.name}' line {index}"
            bhf_id = _str(row.get("id"))
            if bhf_id is None:
                raise IngestorError(f"{where}: empty id")
            _safe_id(bhf_id, where)
            if bhf_id in seen:
                raise IngestorError(
                    f"{where}: duplicate BHF finding id '{bhf_id}' (line {seen[bhf_id]})"
                )
            seen[bhf_id] = index
            if only is not None and only != bhf_id and only not in _csv_member_ids(row):
                continue
            finding_dir = work_dir / "findings" / bhf_id
            findings.append(
                _build_fuzz_finding(
                    row,
                    _load_finding_doc(finding_dir, work_dir),
                    finding_dir,
                    mapper,
                    reproducer_path=_reproducer_path(finding_dir, work_dir),
                )
            )
        return _merge_same_id(findings)

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
            doc = _load_finding_doc(doc_path.parent, work_dir)
            if doc is None:  # symlinked / escaping finding dir or finding.json
                continue
            if not _is_bhf_finding_doc(doc):
                raise IngestorError(f"'{doc_path}' is not a BHF finding.json")
            key = (
                _str(doc.get("cluster_key_full"))
                or _str(doc.get("signature"))
                or _str(doc.get("id"))
                or doc_path.parent.name
            )
            groups.setdefault(key, []).append((doc_path.parent, doc))
        if not groups:
            raise IngestorError(
                f"'{work_dir}' has no usable BHF finding.json "
                "(every candidate was a symlink or resolved outside the work directory)"
            )

        findings: list[Finding] = []
        for members in groups.values():
            # Highest impact wins; ties keep the first (lowest id) member.
            rep_dir, rep_doc = max(
                members,
                key=lambda m: _IMPACT_RANK.get(
                    (_str(_dict(m[1].get("actionability")).get("impact")) or "").lower(), 0
                ),
            )
            member_ids = [
                _safe_id(_str(doc.get("id")) or d.name, f"'{d / 'finding.json'}'")
                for d, doc in members
                if d is not rep_dir
            ]
            # CWE union, representative first — BHF's findings.csv semantics.
            group_cwes: list[int] = []
            for _, doc in [(rep_dir, rep_doc), *members]:
                for cwe in _parse_cwes(_dict(doc.get("actionability")).get("cwe")):
                    if cwe not in group_cwes:
                        group_cwes.append(cwe)
            findings.append(
                _build_fuzz_finding(
                    None,
                    rep_doc,
                    rep_dir,
                    mapper,
                    reproducer_path=_reproducer_path(rep_dir, work_dir),
                    member_ids=member_ids,
                    count=len(members),
                    group_cwes=group_cwes,
                )
            )
        return _merge_same_id(findings)


def _stable_finding_id(
    *,
    is_static: bool,
    cluster_key_full: str | None,
    signature: str | None,
    rule_id: str | None,
    exception_name: str | None,
    sink_file: str | None,
    sink_line: int | None,
    sink_func: str | None,
    bhf_id: str,
) -> str:
    """Finding.id from BHF's cross-run dedup key, never the run-local ``F-NNNN`` ordinal."""
    if is_static:
        if rule_id and sink_file:
            location = (
                f"{rule_id}:{sink_file}:{sink_line}" if sink_line else f"{rule_id}:{sink_file}"
            )
            return f"bhf-static-{slugify(location)}"
        return f"bhf-static-{slugify(cluster_key_full or signature or bhf_id)}"
    key = cluster_key_full or signature
    if key is None and rule_id and sink_file:
        key = ":".join(
            str(p) for p in (rule_id, exception_name, sink_file, sink_line, sink_func) if p
        )
    return f"bhf-{slugify(key or bhf_id)}"


def _build_fuzz_finding(
    row: dict[str, Any] | None,
    doc: dict[str, Any] | None,
    finding_dir: Path,
    mapper: _PathMapper,
    *,
    reproducer_path: str | None,
    member_ids: list[str] | None = None,
    count: int | None = None,
    group_cwes: list[int] | None = None,
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

    bhf_id = _safe_id(
        _str(r.get("id")) or _str(d.get("id")) or finding_dir.name,
        f"BHF finding '{finding_dir}'",
    )
    impact = (
        _str(r.get("impact")) or _str(act.get("impact")) or _str(d.get("severity")) or ""
    ).lower()
    severity = _IMPACT_SEVERITY.get(impact, _UNKNOWN_SEVERITY)
    cwe_ids = group_cwes or _parse_cwes(r.get("cwe")) or _parse_cwes(act.get("cwe"))

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
    is_static = classification == _STATIC_CLASSIFICATION or confirmation == _STATIC_CONFIRMATION

    # Sink candidates, each mapped in turn — the first that maps to a project
    # path wins. Static rows prefer the CSV (BHF resolves the full path there;
    # static finding.json records may carry only a basename).
    sink = _dict(act.get("sink"))
    doc_sink = (sink.get("file"), sink.get("line"), _str(sink.get("function")))
    csv_sink = (r.get("sink_file"), r.get("sink_line"), _str(r.get("sink_function")))
    target_sink = (target.get("source_path"), target.get("line"), None)
    ordered = [csv_sink, doc_sink] if is_static else [doc_sink, csv_sink]
    if mapper.root is None:
        for abs_candidate in (doc_sink[0], target_sink[0]):
            inferred = _infer_root(abs_candidate, csv_sink[0])
            if inferred is not None:
                mapper = _PathMapper(inferred)
                break
    candidates = [*ordered, target_sink]
    sink_file: str | None = None
    sink_line: int | None = None
    for raw_file, raw_line, _ in candidates:
        mapped = mapper.project_path(raw_file)
        if mapped is not None:
            sink_file, sink_line = mapped, _int(raw_line)
            break
    if sink_file is not None and sink_line is None:
        sink_line = next((v for v in (_int(c[1]) for c in candidates) if v is not None), None)
    func_candidates = [c[2] for c in ordered] + [_str(r.get("entity"))]
    if not is_static:  # a static record's target.name is the file basename
        func_candidates.append(_str(target.get("name")))
    sink_func = next((f for f in func_candidates if f), None)

    refs: list[SourceCodeRef] = []
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

    stable_message = _stable_message(message) if message else None
    explanation = _str(act.get("explanation"))
    desc_parts: list[str] = []
    if explanation:
        desc_parts.append(explanation)
    if stable_message:
        if not explanation:
            desc_parts.append(stable_message)
        elif sanitizer:
            desc_parts.append(f"Sanitizer report ({sanitizer}): {stable_message}")
        else:
            desc_parts.append(f"Detector message: {stable_message}")
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
    if is_static and confirmation:
        tags.append(f"{_TAG_PREFIX}:confirmation:{confirmation}")

    if member_ids is None:
        # BHF lists every group member, the representative included; the
        # convention here (as in the directory path) excludes it.
        member_ids = [m for m in _csv_member_ids(r) if m != bhf_id]

    cluster_key_full = _str(d.get("cluster_key_full"))
    signature = _str(r.get("signature")) or _str(d.get("signature"))
    harness_id = _str(r.get("harness_id")) or _str(d.get("harness_id"))

    fuzz: FuzzEvidence | None = None
    if not is_static:
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
            harness_id=harness_id,
            cluster_key=_str(d.get("cluster_key")),
            signature=signature,
            member_ids=member_ids,
            stack=mapper.stack(exc.get("stack")),
            reproducer_path=reproducer_path,
            replay_command=f"bhf replay --finding {shlex.quote(f'findings/{bhf_id}')}",
            prosthetics_used=prosthetics_used,
            cwe_ids=cwe_ids,
        )

    extra: dict[str, Any] = {
        "bhf_count": count if count is not None else _int(r.get("count")),
        "bhf_input_reachability": _str(d.get("input_reachability")),
        "bhf_dialect": _str(d.get("dialect")),
        "bhf_cluster_key_full": cluster_key_full,
        "bhf_data_flow": mapper.scrub_text(_str(r.get("data_flow")) or "") or None,
        # Raw detector line (ASLR addresses included) kept out of the hashed fields.
        "bhf_sanitizer_message": mapper.scrub_text(message) if message and sanitizer else None,
    }
    if is_static:
        extra.update(
            {
                "bhf_rule_id": rule_id,
                "bhf_confirmation": confirmation,
                "bhf_signature": signature,
                "bhf_member_ids": member_ids or None,
                "bhf_cwe_ids": cwe_ids or None,
            }
        )

    return Finding(
        id=_stable_finding_id(
            is_static=is_static,
            cluster_key_full=cluster_key_full,
            signature=signature,
            rule_id=rule_id,
            exception_name=exception_name,
            sink_file=sink_file,
            sink_line=sink_line,
            sink_func=sink_func,
            bhf_id=bhf_id,
        ),
        title=title,
        severity=severity,
        cwe_id=cwe_ids[0] if cwe_ids else None,
        category=FindingCategory.SAST if is_static else FindingCategory.FUZZ,
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
    """A SARIF log with a ``bhf static`` run.

    The driver name alone is not enough: ``bhf report --sarif`` also names its
    driver ``BHF`` but carries dynamic fuzz findings (``bhfReportSchemaVersion``),
    which are left to the generic SARIF ingestor rather than mislabelled SAST.
    """
    if not (
        isinstance(doc, dict)
        and doc.get("version") == "2.1.0"
        and isinstance(doc.get("runs"), list)
    ):
        return False
    for run in doc["runs"]:
        props = _dict(_dict(run).get("properties"))
        if _str(props.get("bhfStaticSchemaVersion")) or _str(props.get("findingKind")) == "static":
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
            doc = _probe_json(path, _MAX_STATIC_PROBE_BYTES)
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            return False
        return _is_bhf_sarif(doc) or _is_bhf_static_json(doc)

    def extract_scanner_version(self, raw: bytes) -> str | None:
        try:
            doc = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
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
        updates["extra_fields"] = {
            **_sarif_path_provenance(finding.extra_fields, refs),
            **updates["extra_fields"],
        }
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
