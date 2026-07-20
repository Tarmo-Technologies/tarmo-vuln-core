"""Tests for dedup engine — Python fallback and Rust (when available)."""

from __future__ import annotations

import pytest

from tarmo_vuln_core.dedup import deduplicate_findings
from tarmo_vuln_core.dedup.engine import python_deduplicate_findings


def _make_finding_dict(
    id: str = "sqli-001",
    title: str = "SQL Injection",
    severity: str = "HIGH",
    description: str = "SQL injection in login form",
    source_tool: str = "semgrep",
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
        "affected_hosts": affected_hosts or ["10.0.0.1"],
    }


class TestPythonDedup:
    def test_removes_exact_duplicates(self):
        findings = [_make_finding_dict(), _make_finding_dict()]
        result = python_deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["title"] == "SQL Injection"

    def test_preserves_distinct_findings(self):
        findings = [
            _make_finding_dict(id="sqli-001", title="SQL Injection"),
            _make_finding_dict(id="xss-001", title="XSS", description="Cross-site scripting"),
        ]
        result = python_deduplicate_findings(findings)
        assert len(result) == 2
        titles = {f["title"] for f in result}
        assert titles == {"SQL Injection", "XSS"}

    def test_hash_determinism(self):
        """Same finding produces the same hash every time."""
        f = _make_finding_dict()
        result1 = python_deduplicate_findings([f, f])
        result2 = python_deduplicate_findings([f, f])
        assert len(result1) == 1
        assert len(result2) == 1

    def test_different_hosts_are_distinct(self):
        f1 = _make_finding_dict(affected_hosts=["10.0.0.1"])
        f2 = _make_finding_dict(affected_hosts=["10.0.0.2"])
        result = python_deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_severity_same_title_distinct(self):
        f1 = _make_finding_dict(severity="HIGH")
        f2 = _make_finding_dict(severity="MEDIUM")
        result = python_deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_empty_input(self):
        result = python_deduplicate_findings([])
        assert result == []

    def test_single_finding(self):
        result = python_deduplicate_findings([_make_finding_dict()])
        assert len(result) == 1

    def test_preserves_order_first_seen(self):
        """First occurrence of each unique finding is kept."""
        f1 = _make_finding_dict(id="a", title="First")
        f2 = _make_finding_dict(id="b", title="Second")
        f3 = _make_finding_dict(id="a", title="First")  # duplicate of f1
        result = python_deduplicate_findings([f1, f2, f3])
        assert len(result) == 2
        assert result[0]["title"] == "First"
        assert result[1]["title"] == "Second"

    def test_large_batch_dedup(self):
        """Dedup works correctly on 1000+ findings."""
        findings = []
        for i in range(500):
            findings.append(_make_finding_dict(id=f"vuln-{i}", title=f"Vuln {i}"))
        # Duplicate the whole batch
        findings.extend(findings[:500])
        assert len(findings) == 1000
        result = python_deduplicate_findings(findings)
        assert len(result) == 500


class TestDispatchDedup:
    """Test the dispatch function which uses Rust when available, else Python."""

    def test_dedup_works(self):
        findings = [_make_finding_dict(), _make_finding_dict()]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["title"] == "SQL Injection"

    def test_dispatch_matches_python(self):
        findings = [
            _make_finding_dict(id="a", title="Alpha"),
            _make_finding_dict(id="b", title="Beta"),
            _make_finding_dict(id="a", title="Alpha"),  # duplicate
        ]
        dispatch_result = deduplicate_findings(findings)
        python_result = python_deduplicate_findings(findings)
        assert len(dispatch_result) == len(python_result) == 2


class TestRustDedup:
    """Tests that only run when the Rust extension is available."""

    @pytest.fixture(autouse=True)
    def _require_rust(self):
        mod = pytest.importorskip("vuln_core_rs")
        if not hasattr(mod, "deduplicate_findings"):
            pytest.skip("vuln_core_rs.deduplicate_findings not available (rebuild needed)")

    def test_rust_dedup_matches_python(self):
        from vuln_core_rs import deduplicate_findings as rust_dedup

        findings = [
            _make_finding_dict(id="a", title="Alpha"),
            _make_finding_dict(id="b", title="Beta"),
            _make_finding_dict(id="a", title="Alpha"),
        ]
        rust_result = rust_dedup(findings)
        python_result = python_deduplicate_findings(findings)
        assert len(rust_result) == len(python_result)

    def test_rust_large_batch(self):
        from vuln_core_rs import deduplicate_findings as rust_dedup

        findings = [_make_finding_dict(id=f"v-{i}", title=f"V {i}") for i in range(1000)]
        findings.extend(findings[:1000])
        result = rust_dedup(findings)
        assert len(result) == 1000
