"""Diff engine — compute changes between two sets of findings."""

from __future__ import annotations

from pydantic import BaseModel

from tarmo_vuln_core.models import Finding, Severity


class ChangedFinding(BaseModel):
    """A finding that changed between two scans."""

    finding: Finding
    old_severity: Severity
    new_severity: Severity
    hosts_added: list[str] = []
    hosts_removed: list[str] = []

    @property
    def severity_increased(self) -> bool:
        """True when new severity is higher (worse) than old."""
        return self.new_severity > self.old_severity

    @property
    def is_regression(self) -> bool:
        """True when severity increased or new hosts appeared."""
        return self.severity_increased or len(self.hosts_added) > 0


class DiffResult(BaseModel):
    """Result of diffing two finding sets."""

    new: list[Finding] = []
    resolved: list[Finding] = []
    changed: list[ChangedFinding] = []

    @property
    def has_regressions(self) -> bool:
        """True if there are any new findings or any changed finding is a regression."""
        if self.new:
            return True
        return any(c.is_regression for c in self.changed)


def diff_findings(before: list[Finding], after: list[Finding]) -> DiffResult:
    """Compute the diff between two lists of findings, matched by finding id.

    Returns a DiffResult with new, resolved, and changed findings.
    All output lists are sorted by finding id.
    """
    before_map: dict[str, Finding] = {f.id: f for f in before}
    after_map: dict[str, Finding] = {f.id: f for f in after}

    before_ids = set(before_map.keys())
    after_ids = set(after_map.keys())

    new_ids = after_ids - before_ids
    resolved_ids = before_ids - after_ids
    common_ids = before_ids & after_ids

    new = sorted([after_map[fid] for fid in new_ids], key=lambda f: f.id)
    resolved = sorted([before_map[fid] for fid in resolved_ids], key=lambda f: f.id)

    changed: list[ChangedFinding] = []
    for fid in sorted(common_ids):
        old_f = before_map[fid]
        new_f = after_map[fid]

        old_hosts = set(old_f.affected_hosts)
        new_hosts = set(new_f.affected_hosts)

        severity_changed = old_f.severity != new_f.severity
        hosts_added = sorted(new_hosts - old_hosts)
        hosts_removed = sorted(old_hosts - new_hosts)

        if severity_changed or hosts_added or hosts_removed:
            changed.append(
                ChangedFinding(
                    finding=new_f,
                    old_severity=old_f.severity,
                    new_severity=new_f.severity,
                    hosts_added=hosts_added,
                    hosts_removed=hosts_removed,
                )
            )

    return DiffResult(new=new, resolved=resolved, changed=changed)
