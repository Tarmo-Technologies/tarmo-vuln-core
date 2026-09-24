"""OWASP Dependency-Check JSON ingestor."""

from __future__ import annotations

import json
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."
_IGNORED_CWE_VALUES = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER"}


def _parse_cwe_id(cwes: list[object]) -> int | None:
    for value in cwes:
        text = str(value).strip()
        if not text:
            continue
        upper = text.upper()
        if upper in _IGNORED_CWE_VALUES:
            continue
        if upper.startswith("CWE-") and upper[4:].isdigit():
            return int(upper[4:])
        if text.isdigit():
            return int(text)
    return None


class OwaspDepcheckIngestor(BaseIngestor):
    """Parses OWASP Dependency-Check JSON output files."""

    category = FindingCategory.SCA

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return False
            # Check for reportSchema containing "dependency-check"
            schema = data.get("reportSchema", "")
            return "dependency-check" in str(schema).lower()
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Dependency-Check JSON: {e}") from e

        # Group vulns by CVE name, collect affected deps
        vuln_groups: dict[str, dict] = {}
        seen_cves: set[str] = set()

        for dep in data.get("dependencies", []):
            dep_name = dep.get("fileName", "")
            for vuln in dep.get("vulnerabilities", []):
                cve_name = vuln.get("name", "")
                if not cve_name:
                    continue

                if cve_name not in seen_cves:
                    seen_cves.add(cve_name)
                    cwes = vuln.get("cwes", [])
                    cwe_id = _parse_cwe_id(cwes) if isinstance(cwes, list) else None

                    vuln_groups[cve_name] = {
                        "severity": vuln.get("severity", "MEDIUM"),
                        "description": vuln.get("description", ""),
                        "cwe_id": cwe_id,
                        "affected_deps": [dep_name] if dep_name else [],
                    }
                else:
                    # Add this dep to existing group
                    if dep_name and dep_name not in vuln_groups[cve_name]["affected_deps"]:
                        vuln_groups[cve_name]["affected_deps"].append(dep_name)

        findings: list[Finding] = []

        for cve_name, group in vuln_groups.items():
            severity = _SEVERITY_MAP.get(group["severity"].upper(), Severity.MEDIUM)
            finding_id = f"depcheck-{slugify(cve_name)}"

            findings.append(
                Finding(
                    id=finding_id,
                    title=cve_name,
                    severity=severity,
                    description=group["description"],
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    source_tool="owasp-depcheck",
                    raw_ref=cve_name,
                    cwe_id=group["cwe_id"],
                    affected_hosts=group["affected_deps"],
                    extra_fields={},
                )
            )

        return findings
