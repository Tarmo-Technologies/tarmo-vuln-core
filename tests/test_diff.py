"""Tests for the diff engine."""

from __future__ import annotations

from tarmo_vuln_core.diff import diff_findings
from tarmo_vuln_core.models import Finding, Severity


def _make_finding(
    fid: str,
    severity: Severity = Severity.MEDIUM,
    hosts: list[str] | None = None,
) -> Finding:
    return Finding(
        id=fid,
        title=f"Finding {fid}",
        severity=severity,
        description="desc",
        impact="impact",
        remediation="remediation",
        source_tool="manual",
        affected_hosts=hosts or [],
    )


class TestDiffFindings:
    def test_identical_sets_empty_diff(self) -> None:
        a = [_make_finding("f1"), _make_finding("f2")]
        b = [_make_finding("f1"), _make_finding("f2")]
        result = diff_findings(a, b)
        assert result.new == []
        assert result.resolved == []
        assert result.changed == []

    def test_added_finding_detected(self) -> None:
        before = [_make_finding("f1")]
        after = [_make_finding("f1"), _make_finding("f2")]
        result = diff_findings(before, after)
        assert len(result.new) == 1
        assert result.new[0].id == "f2"
        assert result.resolved == []
        assert result.changed == []

    def test_removed_finding_detected(self) -> None:
        before = [_make_finding("f1"), _make_finding("f2")]
        after = [_make_finding("f1")]
        result = diff_findings(before, after)
        assert len(result.resolved) == 1
        assert result.resolved[0].id == "f2"
        assert result.new == []
        assert result.changed == []

    def test_severity_change_detected(self) -> None:
        before = [_make_finding("f1", Severity.LOW)]
        after = [_make_finding("f1", Severity.HIGH)]
        result = diff_findings(before, after)
        assert result.new == []
        assert result.resolved == []
        assert len(result.changed) == 1
        ch = result.changed[0]
        assert ch.old_severity == Severity.LOW
        assert ch.new_severity == Severity.HIGH
        assert ch.finding.id == "f1"

    def test_regression_severity_increased(self) -> None:
        before = [_make_finding("f1", Severity.LOW)]
        after = [_make_finding("f1", Severity.CRITICAL)]
        result = diff_findings(before, after)
        ch = result.changed[0]
        assert ch.severity_increased is True
        assert ch.is_regression is True

    def test_severity_decreased_not_regression(self) -> None:
        before = [_make_finding("f1", Severity.HIGH)]
        after = [_make_finding("f1", Severity.LOW)]
        result = diff_findings(before, after)
        ch = result.changed[0]
        assert ch.severity_increased is False
        assert ch.is_regression is False

    def test_host_change_detection(self) -> None:
        before = [_make_finding("f1", hosts=["10.0.0.1", "10.0.0.2"])]
        after = [_make_finding("f1", hosts=["10.0.0.2", "10.0.0.3"])]
        result = diff_findings(before, after)
        assert len(result.changed) == 1
        ch = result.changed[0]
        assert ch.hosts_added == ["10.0.0.3"]
        assert ch.hosts_removed == ["10.0.0.1"]

    def test_host_added_is_regression(self) -> None:
        before = [_make_finding("f1", hosts=["10.0.0.1"])]
        after = [_make_finding("f1", hosts=["10.0.0.1", "10.0.0.2"])]
        result = diff_findings(before, after)
        ch = result.changed[0]
        assert ch.hosts_added == ["10.0.0.2"]
        assert ch.is_regression is True

    def test_has_regressions_with_new_findings(self) -> None:
        before: list[Finding] = []
        after = [_make_finding("f1")]
        result = diff_findings(before, after)
        assert result.has_regressions is True

    def test_has_regressions_false_when_only_resolved(self) -> None:
        before = [_make_finding("f1")]
        after: list[Finding] = []
        result = diff_findings(before, after)
        assert result.has_regressions is False

    def test_output_sorted_by_id(self) -> None:
        before = [_make_finding("f3"), _make_finding("f1")]
        after = [_make_finding("f5"), _make_finding("f2")]
        result = diff_findings(before, after)
        assert [f.id for f in result.new] == ["f2", "f5"]
        assert [f.id for f in result.resolved] == ["f1", "f3"]
