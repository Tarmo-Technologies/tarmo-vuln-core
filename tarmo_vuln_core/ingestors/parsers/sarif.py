"""SARIF 2.1.0 JSON ingestor."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
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


def _extract_source_code_refs(result: dict) -> list[SourceCodeRef]:
    """Extract source code references from result.locations physicalLocation."""
    refs: list[SourceCodeRef] = []
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation")
        if not phys:
            continue
        artifact = phys.get("artifactLocation", {})
        uri = artifact.get("uri", "")
        if not uri:
            continue
        # Strip file:// prefix for local paths
        if uri.startswith("file:///"):
            uri = uri[len("file:///") :]
        region = phys.get("region", {})
        refs.append(
            SourceCodeRef(
                file_path=uri,
                start_line=region.get("startLine"),
                end_line=region.get("endLine"),
                column=region.get("startColumn"),
                symbol=_extract_symbol(loc),
                snippet=region.get("snippet", {}).get("text", ""),
            )
        )
    return refs


class SarifIngestor(BaseIngestor):
    """Parses SARIF 2.1.0 JSON output files."""

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
                source_refs = _extract_source_code_refs(result)

                findings.append(
                    Finding(
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
                    )
                )

        return findings
