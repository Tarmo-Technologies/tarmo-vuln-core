"""Correlator engine — dispatches to Rust when available, falls back to Python."""

from __future__ import annotations

from typing import Any


def correlate_findings(
    findings: list[dict[str, Any]],
    *,
    threshold: float = 0.8,
    severity_thresholds: dict[str, float] | None = None,
) -> list[tuple[int, int, float]]:
    """Find pairs of correlated findings above the similarity threshold.

    Uses Rust extension if available, else Python fallback.

    Args:
        findings: List of finding dicts with keys like title, description,
            severity, cwe_id, affected_hosts.
        threshold: Global similarity threshold (0.0-1.0). Default 0.8.
        severity_thresholds: Optional per-severity overrides, e.g.
            {"CRITICAL": 0.90, "LOW": 0.60}. The higher-severity finding's
            threshold is used for each pair.

    Returns:
        List of (index_a, index_b, similarity_score) tuples.
    """
    try:
        from vuln_core_rs import (  # type: ignore[import-untyped]
            correlate_findings as rust_correlate,
        )

        return [
            (int(a), int(b), float(s))
            for a, b, s in rust_correlate(findings, threshold, severity_thresholds)
        ]
    except ImportError:
        from tarmo_vuln_core.correlator.engine import python_correlate_findings

        return python_correlate_findings(
            findings, threshold=threshold, severity_thresholds=severity_thresholds
        )
