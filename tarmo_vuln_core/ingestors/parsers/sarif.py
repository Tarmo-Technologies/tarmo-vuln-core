"""SARIF 2.1.0 JSON ingestor."""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify as _slugify

_LEVEL_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

_DEFAULT_DESCRIPTION = "A security issue was identified by static analysis."
_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."


def _severity_from_security_score(score: float, level_fallback: str) -> Severity:
    """Map a numeric security-severity score to a Severity level."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_security_severity(rule: dict) -> float | None:
    """Extract numeric security-severity from rule.properties, if present."""
    props = rule.get("properties", {})
    # Can be a float/int value directly
    val = props.get("security-severity")
    if val is not None:
        try:
            return float(val)
        except (ValueError, TypeError):
            pass
    # Or embedded in tags as "security-severity: 7.5"
    for tag in props.get("tags", []):
        m = re.match(r"security-severity\s*:\s*(\d+(?:\.\d+)?)", str(tag), re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


def _parse_cwe(rule: dict) -> int | None:
    """Extract CWE ID from rule relationships or tags.

    Checks three locations in order:
    1. rule.relationships where toolComponent.name == "CWE"
    2. rule.properties.tags matching "cwe:CWE-<id>"
    3. rule.properties.tags matching "CWE-<id>: <description>" (Semgrep format)
    """
    for rel in rule.get("relationships", []):
        target = rel.get("target", {})
        tool_comp = target.get("toolComponent", {})
        if tool_comp.get("name") == "CWE":
            cwe_raw = target.get("id", "")
            m = re.match(r"CWE-(\d+)", cwe_raw, re.IGNORECASE)
            if m:
                return int(m.group(1))
    props = rule.get("properties", {})
    for tag in props.get("tags", []):
        tag_str = str(tag)
        # Format: "cwe:CWE-79"
        m = re.match(r"cwe:CWE-(\d+)", tag_str, re.IGNORECASE)
        if m:
            return int(m.group(1))
        # Format: "CWE-89: Improper Neutralization..." (Semgrep style)
        m = re.match(r"CWE-(\d+)\b", tag_str, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None


def _extract_hosts(result: dict) -> list[str]:
    """Extract affected hosts from result.locations (logicalLocations with kind='host')."""
    hosts: list[str] = []
    for loc in result.get("locations", []):
        for ll in loc.get("logicalLocations", []):
            if ll.get("kind") == "host":
                name = ll.get("name", "").strip()
                if name and name not in hosts:
                    hosts.append(name)
    return hosts


def _extract_symbol(loc: dict) -> str | None:
    """Pull a symbol name from SARIF logicalLocations.

    Prefers ``fullyQualifiedName`` (more specific) over ``name``. Returns the
    first usable string, or None if logicalLocations are missing or empty.
    """
    logical = loc.get("logicalLocations") or []
    for entry in logical:
        fqn = entry.get("fullyQualifiedName")
        if fqn:
            return str(fqn)
        name = entry.get("name")
        if name:
            return str(name)
    return None


# uriBaseId names that denote the analysed source tree (compared after dropping
# ``%`` delimiters, ``_``/``-`` and case): ``%SRCROOT%``, ``SRC_ROOT``, ``REPO_ROOT`` ...
_SOURCE_ROOT_BASE_IDS = frozenset(
    {"SRCROOT", "SOURCEROOT", "PROJECTROOT", "REPOROOT", "WORKSPACE", "WORKSPACEROOT"}
)
# Artifact roles that mark a file as not under version control (build output).
_GENERATED_ROLES = frozenset({"uncontrolled"})
_MAX_BASE_CHAIN = 32
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def _is_source_root_id(base_id: str) -> bool:
    return base_id.strip("%").replace("_", "").replace("-", "").upper() in _SOURCE_ROOT_BASE_IDS


def _uri_to_path(uri: str) -> tuple[str, bool]:
    """Decode a SARIF URI reference into ``(path, is_absolute)``.

    ``file:///home/ci/x.c`` keeps its leading ``/``; ``file:///C:/x.c`` becomes
    ``C:/x.c``; ``file://host/share/x.c`` becomes ``//host/share/x.c``.
    Percent-encoding is decoded. Non-file schemes are returned unchanged.
    """
    if uri[:5].lower() == "file:":
        parts = urlsplit(uri)
        path = unquote(parts.path)
        if parts.netloc and parts.netloc.lower() != "localhost":
            return f"//{parts.netloc}{path}", True
        if _WINDOWS_DRIVE_RE.match(path[1:]):
            path = path[1:]
        return path, True
    if "://" in uri:
        return uri, False
    path = unquote(uri)
    return path, path.startswith("/") or bool(_WINDOWS_DRIVE_RE.match(path))


def _join(base: str, rel: str) -> str:
    if not base:
        return rel
    joined = base.rstrip("/") + "/" + rel if rel else base
    if "./" in joined:
        trailing = joined.endswith("/")
        joined = posixpath.normpath(joined) + ("/" if trailing else "")
    return joined


def _expand_base(path: str, base_id: str, bases: dict[str, Any]) -> tuple[str, bool]:
    """Prefix *path* with the chain of ``originalUriBaseIds`` rooted at *base_id*.

    Returns ``(path, is_absolute)``. Expansion stops at a base with no ``uri``
    (an undefined root such as ``%SRCROOT%`` without a value), a missing base or
    a cycle; the path is then still relative to that base.
    """
    current: str | None = base_id
    seen: set[str] = set()
    while current is not None and current not in seen and len(seen) < _MAX_BASE_CHAIN:
        seen.add(current)
        entry = bases.get(current)
        if not isinstance(entry, dict):
            break
        base_uri = entry.get("uri")
        if not isinstance(base_uri, str) or not base_uri:
            break
        base_path, absolute = _uri_to_path(base_uri)
        path = _join(base_path, path)
        if absolute:
            return path, True
        parent = entry.get("uriBaseId")
        current = parent if isinstance(parent, str) and parent else None
    return path, False


@dataclass
class _RunContext:
    """Per-run lookup state for resolving artifact locations."""

    bases: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Any] = field(default_factory=list)
    artifact_by_location: dict[tuple[str, str | None], dict[str, Any]] = field(default_factory=dict)
    source_root: str | None = None

    @classmethod
    def from_run(cls, run: dict[str, Any]) -> _RunContext:
        bases = run.get("originalUriBaseIds")
        bases = bases if isinstance(bases, dict) else {}
        artifacts = run.get("artifacts")
        artifacts = artifacts if isinstance(artifacts, list) else []
        by_location: dict[tuple[str, str | None], dict[str, Any]] = {}
        for artifact in artifacts:
            loc = artifact.get("location") if isinstance(artifact, dict) else None
            if isinstance(loc, dict) and isinstance(loc.get("uri"), str):
                by_location.setdefault((loc["uri"], loc.get("uriBaseId")), artifact)
        source_root = None
        for base_id in bases:
            if isinstance(base_id, str) and _is_source_root_id(base_id):
                root, absolute = _expand_base("", base_id, bases)
                if absolute and root:
                    source_root = root.rstrip("/") + "/"
                break
        return cls(bases, artifacts, by_location, source_root)

    def artifact_at(self, index: object) -> dict[str, Any] | None:
        if (
            isinstance(index, int)
            and not isinstance(index, bool)
            and 0 <= index < len(self.artifacts)
        ):
            artifact = self.artifacts[index]
            if isinstance(artifact, dict):
                return artifact
        return None


def _generated_hint(artifact: dict[str, Any], roles: list[str]) -> bool:
    if _GENERATED_ROLES.intersection(roles):
        return True
    props = artifact.get("properties")
    if not isinstance(props, dict):
        return False
    if props.get("generated") is True:
        return True
    tags = props.get("tags")
    return isinstance(tags, list) and any(str(t).lower() == "generated" for t in tags)


def _resolve_artifact_location(
    artifact_location: dict[str, Any], ctx: _RunContext
) -> tuple[str, dict[str, Any]] | None:
    """Resolve a SARIF ``artifactLocation`` to ``(file_path, provenance)``.

    Rules:

    * ``uriBaseId`` is expanded through ``run.originalUriBaseIds`` (chains allowed).
    * An absolute result that falls under the run's source root (``%SRCROOT%``
      and friends) is re-expressed relative to it, so in-tree files stay
      repo-relative whichever base the tool used.
    * Any other absolute result (out-of-tree build dir, system header) is kept
      absolute with its leading ``/``; downstream strip rules decide what it is.
    * A base that cannot be expanded (no ``uri``) leaves the path relative.

    ``provenance`` always carries ``file_path`` and the raw ``uri``; it adds
    ``uri_base_id``, ``resolved_path`` (absolute path, when a base was expanded
    or it differs from ``file_path``), ``artifact_roles`` and ``generated_hint``
    (``True`` for an ``uncontrolled`` role or a ``generated`` artifact property/tag)
    only when present.
    """
    uri = artifact_location.get("uri")
    base_id = artifact_location.get("uriBaseId")
    artifact = ctx.artifact_at(artifact_location.get("index"))
    if not uri and artifact is not None:
        art_loc = artifact.get("location")
        if isinstance(art_loc, dict):
            uri = art_loc.get("uri")
            base_id = base_id or art_loc.get("uriBaseId")
    if not isinstance(uri, str) or not uri:
        return None
    if not isinstance(base_id, str) or not base_id:
        base_id = None
    if artifact is None:
        artifact = ctx.artifact_by_location.get((uri, base_id))

    path, absolute = _uri_to_path(uri)
    expanded = False
    if not absolute and base_id is not None:
        path, absolute = _expand_base(path, base_id, ctx.bases)
        expanded = absolute
    file_path = path
    if absolute and ctx.source_root and path.startswith(ctx.source_root):
        file_path = path[len(ctx.source_root) :]

    provenance: dict[str, Any] = {"file_path": file_path, "uri": uri}
    if base_id is not None:
        provenance["uri_base_id"] = base_id
    if absolute and (expanded or path != file_path):
        provenance["resolved_path"] = path
    if artifact is not None:
        raw_roles = artifact.get("roles")
        roles = [r for r in raw_roles if isinstance(r, str)] if isinstance(raw_roles, list) else []
        if roles:
            provenance["artifact_roles"] = roles
        if _generated_hint(artifact, roles):
            provenance["generated_hint"] = True
    return file_path, provenance


def _extract_locations(
    result: dict, ctx: _RunContext | None = None
) -> list[tuple[SourceCodeRef, dict[str, Any]]]:
    """Extract ``(SourceCodeRef, provenance)`` pairs from result.locations."""
    ctx = ctx or _RunContext()
    out: list[tuple[SourceCodeRef, dict[str, Any]]] = []
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation")
        if not phys:
            continue
        artifact = phys.get("artifactLocation", {})
        if not isinstance(artifact, dict):
            continue
        resolved = _resolve_artifact_location(artifact, ctx)
        if resolved is None:
            continue
        file_path, provenance = resolved
        region = phys.get("region", {})
        ref = SourceCodeRef(
            file_path=file_path,
            start_line=region.get("startLine"),
            end_line=region.get("endLine"),
            column=region.get("startColumn"),
            symbol=_extract_symbol(loc),
            snippet=region.get("snippet", {}).get("text", ""),
        )
        provenance["file_path"] = ref.file_path
        out.append((ref, provenance))
    return out


def _extract_source_code_refs(result: dict, ctx: _RunContext | None = None) -> list[SourceCodeRef]:
    """Extract source code references from result.locations physicalLocation."""
    return [ref for ref, _ in _extract_locations(result, ctx)]


_PROVENANCE_KEYS = ("uri_base_id", "resolved_path", "artifact_roles", "generated_hint")


def _provenance_extra_fields(provenance: list[dict[str, Any]]) -> dict[str, Any]:
    """Finding-level extra_fields for path provenance.

    ``path_provenance`` is aligned index-for-index with ``source_code_refs``;
    the flat keys mirror the primary (first) location for simple consumers.
    Empty when no location carries a base id, resolved path or artifact marker.
    """
    if not any(key in entry for entry in provenance for key in _PROVENANCE_KEYS):
        return {}
    extra: dict[str, Any] = {"path_provenance": provenance}
    for key in _PROVENANCE_KEYS:
        if key in provenance[0]:
            extra[key] = provenance[0][key]
    return extra


class SarifIngestor(BaseIngestor):
    """Parses SARIF 2.1.0 JSON output files."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".json", ".sarif"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a SARIF 2.1.0 JSON report.

        Checks that the JSON has version == "2.1.0" and a non-empty "runs" list.
        """
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return (
                isinstance(data, dict)
                and data.get("version") == "2.1.0"
                and isinstance(data.get("runs"), list)
            )
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a SARIF 2.1.0 JSON file and return a list of Finding objects.

        Each SARIF result becomes one Finding. Rules are looked up from the
        tool driver to enrich title, description, remediation, and CWE.
        Severity is derived from result.level with optional upgrade based on
        rule.properties.security-severity.

        Args:
            path: Path to the SARIF JSON file.

        Returns:
            List of Finding objects, one per SARIF result.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse SARIF JSON: {e}") from e

        findings: list[Finding] = []

        for run in data.get("runs", []):
            ctx = _RunContext.from_run(run)
            driver = run.get("tool", {}).get("driver", {})
            rules_list: list[dict] = driver.get("rules", [])

            # Build rule index by id for fast lookup
            rule_by_id: dict[str, dict] = {r.get("id", ""): r for r in rules_list}

            for result in run.get("results", []):
                rule_id = result.get("ruleId") or ""

                # Fall back to ruleIndex if ruleId is absent
                if not rule_id:
                    rule_idx = result.get("ruleIndex")
                    if rule_idx is not None and rule_idx < len(rules_list):
                        rule_id = rules_list[rule_idx].get("id", "")

                rule = rule_by_id.get(rule_id, {})

                # Title: rule.name → rule.shortDescription.text → rule.id → "Unknown"
                title = (
                    rule.get("name")
                    or rule.get("shortDescription", {}).get("text")
                    or rule_id
                    or "Unknown"
                )

                # Description: result.message.text → rule.fullDescription.text → default
                description = (
                    result.get("message", {}).get("text")
                    or rule.get("fullDescription", {}).get("text")
                    or _DEFAULT_DESCRIPTION
                )

                # Remediation: rule.help.text → default
                remediation = rule.get("help", {}).get("text") or _DEFAULT_REMEDIATION

                # Severity: start from level, upgrade with security-severity if present
                level = result.get("level", "warning")
                severity = _LEVEL_SEVERITY.get(level, Severity.MEDIUM)
                sec_score = _parse_security_severity(rule)
                if sec_score is not None:
                    severity = _severity_from_security_score(sec_score, level)

                cwe_id = _parse_cwe(rule)
                hosts = _extract_hosts(result)
                locations = _extract_locations(result, ctx)
                source_refs = [ref for ref, _ in locations]

                finding = Finding(
                    id=f"sarif-{_slugify(rule_id or title)}",
                    title=str(title),
                    severity=severity,
                    description=str(description),
                    impact=_DEFAULT_IMPACT,
                    remediation=str(remediation),
                    cwe_id=cwe_id,
                    affected_hosts=hosts,
                    source_code_refs=source_refs,
                    source_tool="sarif",
                    raw_ref=rule_id or None,
                    extra_fields=_provenance_extra_fields([prov for _, prov in locations]),
                )
                findings.append(self._customize_finding(finding, result=result, rule=rule))

        return findings

    def _customize_finding(self, finding: Finding, *, result: dict, rule: dict) -> Finding:
        """Hook for tool-specific SARIF subclasses to enrich a generic finding.

        Called once per SARIF result with the raw ``result`` object and its
        resolved ``rule`` (``{}`` when the driver declares none). The default
        returns *finding* unchanged.
        """
        return finding
