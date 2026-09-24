"""Fortify FPR (FVDL XML inside ZIP) ingestor."""

from __future__ import annotations

import re
import zipfile
from collections.abc import Iterable
from os.path import basename
from pathlib import Path
from typing import IO
from xml.etree.ElementTree import Element

from tarmo_vuln_core.ingestors._xml import parse_xml_bytes, parse_xml_file
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_NS = "xmlns://www.fortifysoftware.com/schema/fvdl"
_NSP = f"{{{_NS}}}"

#: Default ceiling on the decompressed size of ``audit.fvdl`` inside an ``.fpr``
#: archive (zip-bomb guard). Override per instance with
#: ``FortifyIngestor(max_fvdl_bytes=...)``.
MAX_FVDL_BYTES = 512 * 1024 * 1024

_READ_CHUNK = 1024 * 1024

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


def _read_bounded(fh: IO[bytes], *, max_bytes: int, label: str) -> bytes:
    """Read *fh* in fixed-size chunks, refusing to buffer more than *max_bytes*.

    Enforced on the bytes actually produced by the decompressor, so a zip
    header that under-reports ``file_size`` cannot bypass the cap.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = fh.read(min(_READ_CHUNK, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise IngestorError(
                f"Fortify {label} exceeds the decompressed size cap of {max_bytes} bytes"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_fvdl_bytes(path: Path, max_bytes: int = MAX_FVDL_BYTES) -> bytes:
    if path.suffix.lower() == ".fpr" or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                info = zf.getinfo("audit.fvdl")
                if info.file_size > max_bytes:
                    raise IngestorError(
                        f"Fortify audit.fvdl in '{path.name}' declares {info.file_size} bytes, "
                        f"which exceeds the decompressed size cap of {max_bytes} bytes"
                    )
                with zf.open(info) as fh:
                    return _read_bounded(fh, max_bytes=max_bytes, label="audit.fvdl")
        except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, OSError, EOFError) as e:
            raise IngestorError(f"Failed to read FPR '{path.name}': {e}") from e

    try:
        data = path.read_bytes()
    except OSError as e:
        raise IngestorError(f"Failed to read Fortify report: {e}") from e

    return data


def _parse_fvdl_root(data: bytes, source: str) -> Element:
    root = parse_xml_bytes(data, fmt="Fortify FVDL", source=source)

    if root.tag != f"{_NSP}FVDL":
        raise IngestorError("Unsupported Fortify XML root element")

    return root


def _iter_rule_groups(rule: Element) -> Iterable[Element]:
    meta = rule.find(f"{_NSP}MetaInfo")
    if meta is None:
        return ()
    return meta.findall(f"{_NSP}Group")


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
            (defaults to :data:`MAX_FVDL_BYTES`, 512 MiB).
    """

    category = FindingCategory.SAST

    def __init__(self, max_fvdl_bytes: int | None = None) -> None:
        cap = MAX_FVDL_BYTES if max_fvdl_bytes is None else max_fvdl_bytes
        if cap <= 0:
            raise ValueError(f"max_fvdl_bytes must be positive, got {cap}")
        self._max_fvdl_bytes = cap

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
            return parse_xml_file(path, fmt="Fortify FVDL").tag == f"{_NSP}FVDL"
        except (IngestorError, zipfile.BadZipFile, OSError, EOFError):
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        root = _parse_fvdl_root(
            _extract_fvdl_bytes(path, self._max_fvdl_bytes), source=f"'{path.name}'"
        )

        # Build CWE map from Description/Rule elements
        cwe_map: dict[str, int | None] = {}
        desc_el = root.find(f"{_NSP}Description")
        if desc_el is not None:
            for rule in desc_el.findall(f"{_NSP}Rule"):
                rule_id = rule.get("ruleID", "")
                for group in _iter_rule_groups(rule):
                    if group.get("name") == "altcategoryCWE" and group.text:
                        m = re.search(r"(\d+)", group.text)
                        if m:
                            cwe_map[rule_id] = int(m.group(1))

        normalized_cwe_map = {
            rule_id: _expanded_normalized_keys(rule_id) for rule_id in cwe_map if rule_id
        }

        findings: list[Finding] = []

        vulns_el = root.find(f"{_NSP}Vulnerabilities")
        if vulns_el is None:
            return []

        for vuln in vulns_el.findall(f"{_NSP}Vulnerability"):
            class_info = vuln.find(f"{_NSP}ClassInfo")
            if class_info is None:
                continue

            vuln_type_el = class_info.find(f"{_NSP}Type")
            vuln_type = (
                vuln_type_el.text if vuln_type_el is not None and vuln_type_el.text else "Unknown"
            )

            sev_el = class_info.find(f"{_NSP}DefaultSeverity")
            sev_val = float(sev_el.text) if sev_el is not None and sev_el.text else 3.0
            severity = _severity_from_float(sev_val)

            # Trace locations
            source_refs: list[SourceCodeRef] = []
            first_file = ""
            first_line: int | None = None

            analysis = vuln.find(f"{_NSP}AnalysisInfo")
            if analysis is not None:
                unified = analysis.find(f"{_NSP}Unified")
                if unified is not None:
                    trace = unified.find(f"{_NSP}Trace")
                    if trace is not None:
                        primary = trace.find(f"{_NSP}Primary")
                        if primary is not None:
                            for entry in primary.findall(f"{_NSP}Entry"):
                                node = entry.find(f"{_NSP}Node")
                                if node is not None:
                                    src_loc = node.find(f"{_NSP}SourceLocation")
                                    if src_loc is not None:
                                        loc_path = src_loc.get("path", "")
                                        loc_line_str = src_loc.get("line", "")
                                        loc_line = (
                                            int(loc_line_str) if loc_line_str.isdigit() else None
                                        )
                                        if loc_path:
                                            source_refs.append(
                                                SourceCodeRef(
                                                    file_path=loc_path,
                                                    start_line=loc_line,
                                                )
                                            )
                                            if not first_file:
                                                first_file = loc_path
                                                first_line = loc_line

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
