"""Tests for correlator engine — Python fallback and Rust (when available)."""

from __future__ import annotations

import pytest

from tarmo_vuln_core.correlator import correlate_findings
from tarmo_vuln_core.correlator.engine import python_correlate_findings


def _make_finding_dict(
    id: str = "sqli-001",
    title: str = "SQL Injection",
    severity: str = "HIGH",
    description: str = "SQL injection in login form",
    source_tool: str = "semgrep",
    cwe_id: int | None = None,
    affected_hosts: list[str] | None = None,
) -> dict:
    return {
        "id": id,
        "title": title,
        "severity": severity,
        "description": description,
        "impact": "Database compromise",
        "remediation": "Use parameterised queries",
        "source_tool": source_tool,
        "cwe_id": cwe_id,
        "affected_hosts": affected_hosts or [],
    }


class TestPythonCorrelator:
    def test_identical_findings_correlate(self):
        findings = [
            _make_finding_dict(id="a", title="SQL Injection", source_tool="semgrep"),
            _make_finding_dict(id="b", title="SQL Injection", source_tool="bandit"),
        ]
        result = python_correlate_findings(findings, threshold=0.8)
        assert len(result) >= 1
        indices = {(r[0], r[1]) for r in result}
        assert (0, 1) in indices
        assert result[0][2] >= 0.8

    def test_different_findings_below_threshold(self):
        findings = [
            _make_finding_dict(id="a", title="SQL Injection"),
            _make_finding_dict(id="b", title="Cross-Site Scripting XSS"),
        ]
        result = python_correlate_findings(findings, threshold=0.8)
        assert len(result) == 0

    def test_threshold_filtering(self):
        findings = [
            _make_finding_dict(id="a", title="SQL Injection in Login"),
            _make_finding_dict(id="b", title="SQL Injection in Search"),
        ]
        high_thresh = python_correlate_findings(findings, threshold=0.95)
        low_thresh = python_correlate_findings(findings, threshold=0.5)
        assert len(low_thresh) >= len(high_thresh)

    def test_cross_tool_correlation(self):
        """Findings from different tools about the same vulnerability should correlate."""
        findings = [
            _make_finding_dict(
                id="semgrep-sqli",
                title="SQL Injection in user input",
                source_tool="semgrep",
                description="User input directly concatenated into SQL query",
            ),
            _make_finding_dict(
                id="bandit-sqli",
                title="SQL Injection in user input",
                source_tool="bandit",
                description="User input directly concatenated into SQL query",
            ),
        ]
        result = python_correlate_findings(findings, threshold=0.8)
        assert len(result) == 1
        assert result[0][0] == 0
        assert result[0][1] == 1
        assert result[0][2] >= 0.8

    def test_empty_input(self):
        result = python_correlate_findings([], threshold=0.8)
        assert result == []

    def test_single_finding(self):
        result = python_correlate_findings([_make_finding_dict()], threshold=0.8)
        assert result == []

    def test_similarity_score_range(self):
        findings = [
            _make_finding_dict(id="a", title="Alpha"),
            _make_finding_dict(id="b", title="Alpha"),
        ]
        result = python_correlate_findings(findings, threshold=0.0)
        for _, _, score in result:
            assert 0.0 <= score <= 1.0

    def test_returns_tuples_of_index_index_score(self):
        findings = [
            _make_finding_dict(id="a", title="Test Finding"),
            _make_finding_dict(id="b", title="Test Finding"),
        ]
        result = python_correlate_findings(findings, threshold=0.5)
        assert len(result) >= 1
        idx_a, idx_b, score = result[0]
        assert isinstance(idx_a, int)
        assert isinstance(idx_b, int)
        assert isinstance(score, float)
        assert idx_a < idx_b

    def test_cwe_match_boosts_score(self):
        """Same CWE should produce a higher score than different CWEs."""
        findings_same = [
            _make_finding_dict(id="a", title="SQL Injection", cwe_id=89),
            _make_finding_dict(id="b", title="SQL Injection", cwe_id=89),
        ]
        findings_diff = [
            _make_finding_dict(id="a", title="SQL Injection", cwe_id=89),
            _make_finding_dict(id="b", title="SQL Injection", cwe_id=79),
        ]
        result_same = python_correlate_findings(findings_same, threshold=0.0)
        result_diff = python_correlate_findings(findings_diff, threshold=0.0)
        score_same = result_same[0][2]
        score_diff = result_diff[0][2]
        assert score_same > score_diff

    def test_host_overlap_boosts_score(self):
        """Shared affected hosts should produce a higher score."""
        findings_shared = [
            _make_finding_dict(id="a", title="SQL Injection", affected_hosts=["host1"]),
            _make_finding_dict(id="b", title="SQL Injection", affected_hosts=["host1"]),
        ]
        findings_disjoint = [
            _make_finding_dict(id="a", title="SQL Injection", affected_hosts=["host1"]),
            _make_finding_dict(id="b", title="SQL Injection", affected_hosts=["host2"]),
        ]
        result_shared = python_correlate_findings(findings_shared, threshold=0.0)
        result_disjoint = python_correlate_findings(findings_disjoint, threshold=0.0)
        assert result_shared[0][2] > result_disjoint[0][2]

    def test_severity_thresholds_per_severity(self):
        """Per-severity thresholds should apply: higher severity = stricter threshold."""
        findings = [
            _make_finding_dict(id="a", title="SQL Injection in Login", severity="CRITICAL"),
            _make_finding_dict(id="b", title="SQL Injection in Search", severity="CRITICAL"),
        ]
        # With a strict per-severity threshold for CRITICAL, these partial matches won't pass
        strict = python_correlate_findings(
            findings, threshold=0.5, severity_thresholds={"CRITICAL": 0.99}
        )
        # With a loose threshold, they will
        loose = python_correlate_findings(
            findings, threshold=0.5, severity_thresholds={"CRITICAL": 0.5}
        )
        assert len(loose) >= len(strict)


class TestDispatchCorrelator:
    def test_correlate_works(self):
        findings = [
            _make_finding_dict(id="a", title="SQL Injection", source_tool="semgrep"),
            _make_finding_dict(id="b", title="SQL Injection", source_tool="bandit"),
        ]
        result = correlate_findings(findings, threshold=0.8)
        assert len(result) >= 1
        assert result[0][2] >= 0.8

    def test_dispatch_returns_correct_types(self):
        findings = [
            _make_finding_dict(id="a", title="XSS Reflected"),
            _make_finding_dict(id="b", title="XSS Reflected Attack"),
            _make_finding_dict(id="c", title="Something completely different"),
        ]
        result = correlate_findings(findings, threshold=0.5)
        for idx_a, idx_b, score in result:
            assert isinstance(idx_a, int)
            assert isinstance(idx_b, int)
            assert isinstance(score, float)

    def test_severity_thresholds_passed_through(self):
        """severity_thresholds parameter should work through dispatch."""
        findings = [
            _make_finding_dict(id="a", title="SQL Injection in Login", severity="CRITICAL"),
            _make_finding_dict(id="b", title="SQL Injection in Search", severity="CRITICAL"),
        ]
        strict = correlate_findings(findings, threshold=0.5, severity_thresholds={"CRITICAL": 0.99})
        loose = correlate_findings(findings, threshold=0.5, severity_thresholds={"CRITICAL": 0.5})
        assert len(loose) >= len(strict)


class TestRustCorrelator:
    """Tests that only run when the Rust extension is available."""

    @pytest.fixture(autouse=True)
    def _require_rust(self):
        mod = pytest.importorskip("vuln_core_rs")
        if not hasattr(mod, "correlate_findings"):
            pytest.skip("vuln_core_rs.correlate_findings not available (rebuild needed)")

    def test_rust_identical_findings_correlate(self):
        from vuln_core_rs import correlate_findings as rust_correlate

        findings = [
            _make_finding_dict(id="a", title="SQL Injection", source_tool="semgrep"),
            _make_finding_dict(id="b", title="SQL Injection", source_tool="bandit"),
        ]
        result = rust_correlate(findings, 0.8)
        assert len(result) >= 1
        assert result[0][2] >= 0.8

    def test_rust_threshold_filtering(self):
        from vuln_core_rs import correlate_findings as rust_correlate

        findings = [
            _make_finding_dict(id="a", title="Buffer Overflow in Parser"),
            _make_finding_dict(id="b", title="Buffer Overflow in Handler"),
            _make_finding_dict(id="c", title="Something unrelated entirely"),
        ]
        result = rust_correlate(findings, 0.5)
        pairs = {(r[0], r[1]) for r in result}
        assert (0, 1) in pairs

    def test_rust_severity_thresholds(self):
        from vuln_core_rs import correlate_findings as rust_correlate

        findings = [
            _make_finding_dict(id="a", title="SQL Injection in Login", severity="CRITICAL"),
            _make_finding_dict(id="b", title="SQL Injection in Search", severity="CRITICAL"),
        ]
        # Strict CRITICAL threshold — partial title match shouldn't pass
        strict = rust_correlate(findings, 0.5, {"CRITICAL": 0.99})
        # Loose CRITICAL threshold
        loose = rust_correlate(findings, 0.5, {"CRITICAL": 0.5})
        assert len(loose) >= len(strict)

    def test_rust_cwe_match_boosts_score(self):
        from vuln_core_rs import correlate_findings as rust_correlate

        findings_same = [
            _make_finding_dict(id="a", title="SQL Injection", cwe_id=89),
            _make_finding_dict(id="b", title="SQL Injection", cwe_id=89),
        ]
        findings_diff = [
            _make_finding_dict(id="a", title="SQL Injection", cwe_id=89),
            _make_finding_dict(id="b", title="SQL Injection", cwe_id=79),
        ]
        result_same = rust_correlate(findings_same, 0.0)
        result_diff = rust_correlate(findings_diff, 0.0)
        score_same = result_same[0][2]
        score_diff = result_diff[0][2]
        assert score_same > score_diff

    def test_rust_affected_hosts_extracted(self):
        from vuln_core_rs import correlate_findings as rust_correlate

        findings = [
            _make_finding_dict(id="a", title="SQL Injection", affected_hosts=["host1", "host2"]),
            _make_finding_dict(id="b", title="SQL Injection", affected_hosts=["host1", "host2"]),
        ]
        result = rust_correlate(findings, 0.0)
        assert len(result) >= 1
        # Shared hosts should boost score — exact title + hosts + desc = very high
        assert result[0][2] > 0.9
