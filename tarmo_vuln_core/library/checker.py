"""Completeness rules engine for Finding objects."""

from __future__ import annotations

from dataclasses import dataclass, field

from tarmo_vuln_core.models import Finding, Severity


@dataclass
class CheckResult:
    finding_id: str
    title: str
    severity: Severity
    missing: list[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return len(self.missing) == 0


def check_finding(f: Finding) -> CheckResult:
    """Apply all completeness rules to a single finding."""
    missing: list[str] = []
    if not f.description.strip():
        missing.append("description is empty")
    if not f.remediation.strip():
        missing.append("remediation is empty")
    if not f.affected_hosts:
        missing.append("affected_hosts is empty")
    if not f.impact.strip():
        missing.append("impact is empty")
    if f.severity in (Severity.CRITICAL, Severity.HIGH):
        if not f.evidence:
            missing.append("no evidence attached (required for CRITICAL/HIGH)")
        if f.cvss_score is None:
            missing.append("cvss_score not set (required for CRITICAL/HIGH)")
    return CheckResult(finding_id=f.id, title=f.title, severity=f.severity, missing=missing)


def check_findings(findings: list[Finding]) -> list[CheckResult]:
    return [check_finding(f) for f in findings]
