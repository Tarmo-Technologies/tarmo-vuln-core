"""Dedup engine — dispatches to Rust when available, falls back to Python."""

from __future__ import annotations

from typing import Any

from tarmo_vuln_core.dedup.merge import merge_findings, merge_instances


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings. Uses Rust extension if available, else Python fallback."""
    try:
        from vuln_core_rs import deduplicate_findings as rust_dedup  # type: ignore[import-untyped]

        return list(rust_dedup(findings))
    except ImportError:
        from tarmo_vuln_core.dedup.engine import python_deduplicate_findings

        return python_deduplicate_findings(findings)


__all__ = ["deduplicate_findings", "merge_findings", "merge_instances"]
