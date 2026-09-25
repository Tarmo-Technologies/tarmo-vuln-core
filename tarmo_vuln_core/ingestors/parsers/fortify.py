"""Fortify FPR (FVDL XML inside ZIP) ingestor.

``audit.fvdl`` is stream-parsed: every element is harvested for the few fields
the ingestor needs and then discarded, so peak memory does not grow with the
document size (a whole-tree parse costs ~24 bytes of RAM per input byte, which
turned a ~0.5 MB ``.fpr`` zip bomb into a multi-GiB allocation). Before any
inflation the archive entry is also checked against a decompressed-size cap
and a compression-ratio limit, and both are re-enforced on the bytes the
decompressor actually produces.
"""

from __future__ import annotations

import re
import zipfile
import zlib
from dataclasses import dataclass, field
from os.path import basename
from pathlib import Path
from typing import IO
from xml.etree.ElementTree import Element

from tarmo_vuln_core.ingestors._xml import iterparse_xml, xml_first_tag
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_NS = "xmlns://www.fortifysoftware.com/schema/fvdl"
_NSP = f"{{{_NS}}}"

#: Default ceiling on the decompressed size of ``audit.fvdl`` inside an ``.fpr``
#: archive (zip-bomb guard). Override per instance with
#: ``FortifyIngestor(max_fvdl_bytes=...)``.
MAX_FVDL_BYTES = 64 * 1024 * 1024

#: Default ceiling on ``decompressed / compressed`` for ``audit.fvdl``. Real FVDL
#: deflates roughly 10-50:1; deflate's theoretical maximum is ~1032:1. Override
#: per instance with ``FortifyIngestor(max_compression_ratio=...)``.
MAX_FVDL_COMPRESSION_RATIO = 200

#: The ratio limit only applies once this many bytes have been inflated, so
#: small but very repetitive reports are never false positives.
_RATIO_GRACE_BYTES = 1024 * 1024

_READ_CHUNK = 1024 * 1024

#: Ceiling on simultaneously open FVDL elements. Unclosed elements cannot be
#: cleared while streaming, so without this a few hundred KB of ``<a><a>...``
#: costs gigabytes of RAM (element stack + TreeBuilder + expat tag stack).
#: Real FVDL nests roughly 15 levels deep.
MAX_FVDL_DEPTH = 256

#: Errors zipfile / zlib raise for archives it cannot or will not extract:
#: encrypted entries (RuntimeError), unsupported methods such as deflate64 or
#: AES (NotImplementedError), corrupt streams (zlib.error, BadZipFile on CRC).
_ZIP_ERRORS: tuple[type[Exception], ...] = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    OSError,
    EOFError,
    RuntimeError,
    NotImplementedError,
    ValueError,
    zlib.error,
)

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."
_KEYWORD_ALIASES = {
    "csrf": "cross site request forgery",
    "idor": "insecure direct object reference",
    "rce": "remote code execution",
    "sqli": "sql injection",
    "ssrf": "server side request forgery",
    "xss": "cross site scripting",
}


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _expanded_normalized_keys(value: str) -> set[str]:
    raw = value.lower()
    tokens = [token for token in re.split(r"[^a-z0-9]+", raw) if token]
    if not tokens:
        normalized = _normalize_key(raw)
        return {normalized} if normalized else set()

    expanded_tokens = [_KEYWORD_ALIASES.get(token, token) for token in tokens]
    candidates = {
        " ".join(tokens),
        " ".join(expanded_tokens),
        "".join(tokens),
        "".join(expanded_tokens),
    }

    return {_normalize_key(candidate) for candidate in candidates if candidate}


class _BoundedReader:
    """Read-only file wrapper enforcing the zip-bomb limits while streaming.

    Limits are applied to the bytes actually produced by the underlying reader,
    so a zip header that under-reports ``file_size`` cannot bypass them.
    Archive/decompression errors from the wrapped reader surface as
    :class:`IngestorError`.

    Args:
        fh: The binary stream to wrap (e.g. ``ZipFile.open(...)``).
        max_bytes: Decompressed size cap, or ``None`` for no cap.
        label: Name used in error messages (``"audit.fvdl"``).
        compressed_size: Upper bound on compressed bytes backing *fh*.
        max_ratio: Maximum ``decompressed / compressed_size``, or ``None``.
        source: Describes the container for read errors (``"FPR 'x.fpr'"``).
    """

    def __init__(
        self,
        fh: IO[bytes],
        *,
        max_bytes: int | None,
        label: str,
        compressed_size: int | None = None,
        max_ratio: int | None = None,
        source: str = "Fortify report",
    ) -> None:
        self._fh = fh
        self._max_bytes = max_bytes
        self._label = label
        self._compressed = max(compressed_size or 0, 1)
        self._max_ratio = max_ratio
        self._source = source
        self.total = 0

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            chunks = []
            while chunk := self.read(_READ_CHUNK):
                chunks.append(chunk)
            return b"".join(chunks)
        if self._max_bytes is not None:
            size = min(size, self._max_bytes + 1 - self.total)
        try:
            chunk = self._fh.read(size)
        except _ZIP_ERRORS as exc:
            raise IngestorError(f"Failed to read {self._source}: {exc}") from exc
        self.total += len(chunk)
        if self._max_bytes is not None and self.total > self._max_bytes:
            raise IngestorError(
                f"Fortify {self._label} exceeds the decompressed size cap of "
                f"{self._max_bytes} bytes"
            )
        if (
            self._max_ratio is not None
            and self.total > _RATIO_GRACE_BYTES
            and self.total > self._max_ratio * self._compressed
        ):
            raise IngestorError(
                f"Fortify {self._label} compression ratio exceeds the limit of "
                f"{self._max_ratio}:1 ({self.total} bytes inflated from at most "
                f"{self._compressed} compressed bytes; possible zip bomb)"
            )
        return chunk


@dataclass
class _VulnRecord:
    """Fields harvested from one ``<Vulnerability>`` while streaming."""

    has_class_info: bool = False
    type_text: str | None = None
    severity_text: str | None = None
    refs: list[tuple[str, int | None]] = field(default_factory=list)


@dataclass
class _FvdlData:
    vulns: list[_VulnRecord] = field(default_factory=list)
    cwe_map: dict[str, int | None] = field(default_factory=dict)


# Streaming roles. A child gets a role only when its (parent role, tag) pair is
# listed here; "first" pairs match only the first such child, mirroring the
# ``Element.find`` (first) vs ``findall`` (all) selection of the tree parser.
_FIRST_CHILD_ROLES: dict[tuple[str, str], str] = {
    ("root", f"{_NSP}Vulnerabilities"): "vulns",
    ("root", f"{_NSP}Description"): "desc",
    ("vuln", f"{_NSP}ClassInfo"): "classinfo",
    ("vuln", f"{_NSP}AnalysisInfo"): "analysis",
    ("classinfo", f"{_NSP}Type"): "type",
    ("classinfo", f"{_NSP}DefaultSeverity"): "severity",
    ("analysis", f"{_NSP}Unified"): "unified",
    ("unified", f"{_NSP}Trace"): "trace",
    ("trace", f"{_NSP}Primary"): "primary",
    ("entry", f"{_NSP}Node"): "node",
    ("node", f"{_NSP}SourceLocation"): "srcloc",
    ("rule", f"{_NSP}MetaInfo"): "meta",
}
_EVERY_CHILD_ROLES: dict[tuple[str, str], str] = {
    ("vulns", f"{_NSP}Vulnerability"): "vuln",
    ("primary", f"{_NSP}Entry"): "entry",
    ("desc", f"{_NSP}Rule"): "rule",
    ("meta", f"{_NSP}Group"): "group",
}


def _parse_line(value: str) -> int | None:
    return int(value) if value.isascii() and value.isdigit() else None


def _parse_fvdl_stream(fh: _BoundedReader, source: str) -> _FvdlData:
    """Stream-parse FVDL from *fh*, keeping only the fields the ingestor uses.

    Every element is cleared and detached from its parent as soon as it ends,
    so at most one root-to-leaf path of (empty) elements is alive at a time.
    """
    data = _FvdlData()
    # Per open element: (element, role or None, child tags already seen).
    stack: list[tuple[Element, str | None, set[str]]] = []
    vuln: _VulnRecord | None = None
    entry_loc: tuple[str, int | None] | None = None
    rule_id = ""

    for event, elem in iterparse_xml(fh, fmt="Fortify FVDL", label=source):
        tag = elem.tag
        if event == "start":
            if not stack:
                if tag != f"{_NSP}FVDL":
                    raise IngestorError("Unsupported Fortify XML root element")
                stack.append((elem, "root", set()))
                continue
            _parent, parent_role, seen = stack[-1]
            role: str | None = None
            if parent_role is not None:
                key = (parent_role, tag)
                role = _EVERY_CHILD_ROLES.get(key)
                if role is None and tag not in seen:
                    role = _FIRST_CHILD_ROLES.get(key)
                seen.add(tag)
            if role == "vuln":
                vuln = _VulnRecord()
            elif role == "classinfo" and vuln is not None:
                vuln.has_class_info = True
            elif role == "entry":
                entry_loc = None
            elif role == "srcloc":
                entry_loc = (elem.get("path", ""), _parse_line(elem.get("line", "")))
            elif role == "rule":
                rule_id = elem.get("ruleID", "")
            if len(stack) >= MAX_FVDL_DEPTH:
                raise IngestorError(
                    f"Fortify FVDL element nesting depth exceeds the limit of "
                    f"{MAX_FVDL_DEPTH} in {source} (possible resource-exhaustion attack)"
                )
            stack.append((elem, role, set()))
            continue

        # "end"
        _elem, role, _seen = stack.pop()
        if role == "type" and vuln is not None:
            vuln.type_text = elem.text
        elif role == "severity" and vuln is not None:
            vuln.severity_text = elem.text
        elif role == "entry" and vuln is not None:
            if entry_loc is not None and entry_loc[0]:
                vuln.refs.append(entry_loc)
            entry_loc = None
        elif role == "vuln" and vuln is not None:
            if vuln.has_class_info:
                data.vulns.append(vuln)
            vuln = None
        elif role == "group" and elem.get("name") == "altcategoryCWE" and elem.text:
            m = re.search(r"(\d+)", elem.text)
            if m:
                data.cwe_map[rule_id] = int(m.group(1))

        elem.clear()
        if stack:
            stack[-1][0].remove(elem)

    return data


def _check_fpr_entry(info: zipfile.ZipInfo, path: Path, *, max_bytes: int, max_ratio: int) -> int:
    """Reject an ``audit.fvdl`` entry from its headers alone; return the
    effective compressed size (clamped to the archive's real size so an
    over-reported ``compress_size`` cannot shrink the ratio)."""
    if info.flag_bits & 0x1:
        raise IngestorError(
            f"Fortify audit.fvdl in '{path.name}' is encrypted; "
            "password-protected FPR archives are not supported"
        )
    if info.file_size > max_bytes:
        raise IngestorError(
            f"Fortify audit.fvdl in '{path.name}' declares {info.file_size} bytes, "
            f"which exceeds the decompressed size cap of {max_bytes} bytes"
        )
    compressed = max(min(info.compress_size, path.stat().st_size), 1)
    ratio = info.file_size / compressed
    if info.file_size > _RATIO_GRACE_BYTES and ratio > max_ratio:
        raise IngestorError(
            f"Fortify audit.fvdl in '{path.name}' has a compression ratio of "
            f"{ratio:.0f}:1, which exceeds the limit of {max_ratio}:1 (possible zip bomb)"
        )
    return compressed


def _load_fvdl(path: Path, *, max_bytes: int, max_ratio: int) -> _FvdlData:
    source = f"'{path.name}'"
    if path.suffix.lower() == ".fpr" or zipfile.is_zipfile(path):
        try:
            zf = zipfile.ZipFile(path)
        except _ZIP_ERRORS as e:
            raise IngestorError(f"Failed to read FPR {source}: {e}") from e
        with zf:
            try:
                info = zf.getinfo("audit.fvdl")
            except KeyError as e:
                raise IngestorError(f"Failed to read FPR {source}: {e}") from e
            compressed = _check_fpr_entry(info, path, max_bytes=max_bytes, max_ratio=max_ratio)
            try:
                fh = zf.open(info)
            except _ZIP_ERRORS as e:
                raise IngestorError(f"Failed to read FPR {source}: {e}") from e
            with fh:
                reader = _BoundedReader(
                    fh,
                    max_bytes=max_bytes,
                    label="audit.fvdl",
                    compressed_size=compressed,
                    max_ratio=max_ratio,
                    source=f"FPR {source}",
                )
                return _parse_fvdl_stream(reader, source)

    # Standalone .fvdl: no decompression amplification, so no cap -- but still
    # streamed so memory stays flat regardless of file size.
    try:
        raw = path.open("rb")
    except OSError as e:
        raise IngestorError(f"Failed to read Fortify report: {e}") from e
    with raw:
        reader = _BoundedReader(
            raw, max_bytes=None, label=path.name, source=f"Fortify report {source}"
        )
        return _parse_fvdl_stream(reader, source)


def _severity_from_float(val: float) -> Severity:
    """Map DefaultSeverity float to Severity."""
    if val >= 5.0:
        return Severity.CRITICAL
    if val >= 4.0:
        return Severity.HIGH
    if val >= 3.0:
        return Severity.MEDIUM
    if val >= 2.0:
        return Severity.LOW
    return Severity.INFO


class FortifyIngestor(BaseIngestor):
    """Parses Fortify FPR files (ZIP containing audit.fvdl XML).

    Args:
        max_fvdl_bytes: Ceiling on the decompressed size of ``audit.fvdl``
            (defaults to :data:`MAX_FVDL_BYTES`, 64 MiB).
        max_compression_ratio: Ceiling on ``decompressed / compressed`` for
            ``audit.fvdl`` (defaults to :data:`MAX_FVDL_COMPRESSION_RATIO`).
    """

    category = FindingCategory.SAST

    def __init__(
        self, max_fvdl_bytes: int | None = None, max_compression_ratio: int | None = None
    ) -> None:
        cap = MAX_FVDL_BYTES if max_fvdl_bytes is None else max_fvdl_bytes
        if cap <= 0:
            raise ValueError(f"max_fvdl_bytes must be positive, got {cap}")
        ratio = (
            MAX_FVDL_COMPRESSION_RATIO if max_compression_ratio is None else max_compression_ratio
        )
        if ratio <= 0:
            raise ValueError(f"max_compression_ratio must be positive, got {ratio}")
        self._max_fvdl_bytes = cap
        self._max_compression_ratio = ratio

    @property
    def supported_extensions(self) -> list[str]:
        return [".fpr", ".fvdl"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            if path.suffix.lower() == ".fpr" or zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    return "audit.fvdl" in zf.namelist()
            return xml_first_tag(path, fmt="Fortify FVDL") == f"{_NSP}FVDL"
        except IngestorError:
            return False
        except _ZIP_ERRORS:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        data = _load_fvdl(
            path, max_bytes=self._max_fvdl_bytes, max_ratio=self._max_compression_ratio
        )
        cwe_map = data.cwe_map
        normalized_cwe_map = {
            rule_id: _expanded_normalized_keys(rule_id) for rule_id in cwe_map if rule_id
        }

        findings: list[Finding] = []
        for vuln in data.vulns:
            vuln_type = vuln.type_text if vuln.type_text else "Unknown"

            sev_text = vuln.severity_text
            try:
                sev_val = float(sev_text) if sev_text else 3.0
            except ValueError as e:
                raise IngestorError(
                    f"Fortify vulnerability '{vuln_type}' in '{path.name}' has non-numeric "
                    f"DefaultSeverity {sev_text!r}"
                ) from e
            severity = _severity_from_float(sev_val)

            source_refs = [
                SourceCodeRef(file_path=loc_path, start_line=loc_line)
                for loc_path, loc_line in vuln.refs
            ]
            first_file, first_line = vuln.refs[0] if vuln.refs else ("", None)

            # CWE: try to match by type slug to a rule
            cwe_id: int | None = None
            type_keys = _expanded_normalized_keys(vuln_type)
            for rule_id, rule_keys in normalized_cwe_map.items():
                cwe = cwe_map[rule_id]
                if any(
                    type_key and rule_key and (type_key in rule_key or rule_key in type_key)
                    for type_key in type_keys
                    for rule_key in rule_keys
                ):
                    cwe_id = cwe
                    break

            file_base = basename(first_file) if first_file else "unknown"
            finding_id = f"fortify-{slugify(vuln_type)}-{slugify(file_base)}-l{first_line}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=vuln_type,
                    severity=severity,
                    description=f"{vuln_type} vulnerability detected",
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="fortify",
                    raw_ref=vuln_type,
                    cwe_id=cwe_id,
                    source_code_refs=source_refs,
                    affected_hosts=[first_file] if first_file else [],
                    extra_fields={},
                )
            )

        return findings
