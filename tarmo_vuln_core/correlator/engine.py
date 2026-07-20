"""Pure-Python correlator engine — blocking + weighted scoring fallback.

Uses Tier 1 deterministic blocking to reduce O(n²) to a manageable candidate set,
then applies weighted scoring (Jaro-Winkler on title/description, exact match on
CWE/severity, Jaccard on hosts).  For n < 100, falls back to brute-force pairwise.
"""

from __future__ import annotations

from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _extract(finding: dict[str, Any]) -> dict[str, Any]:
    """Extract structured fields from a finding dict."""
    title = str(finding.get("title", ""))
    description = str(finding.get("description", ""))
    return {
        "title_lower": title.lower(),
        "description": description,
        "severity": str(finding.get("severity", "")),
        "cwe_id": finding.get("cwe_id"),
        "affected_hosts": finding.get("affected_hosts", []) or [],
    }


def _score_pair(a: dict[str, Any], b: dict[str, Any]) -> float:
    """Weighted similarity score between two extracted findings."""
    # Title similarity (SequenceMatcher as Jaro-Winkler substitute)
    title_sim = SequenceMatcher(None, a["title_lower"], b["title_lower"]).ratio()

    # CWE match
    cwe_a, cwe_b = a["cwe_id"], b["cwe_id"]
    if cwe_a is not None and cwe_b is not None:
        cwe_sim = 1.0 if cwe_a == cwe_b else 0.0
    elif cwe_a is None and cwe_b is None:
        cwe_sim = 1.0  # both missing — indistinguishable
    else:
        cwe_sim = 0.5  # one present, one missing — uncertain

    # Host overlap (Jaccard)
    hosts_a = set(a["affected_hosts"])
    hosts_b = set(b["affected_hosts"])
    if hosts_a or hosts_b:
        host_sim = len(hosts_a & hosts_b) / len(hosts_a | hosts_b) if (hosts_a | hosts_b) else 0.0
    else:
        host_sim = 1.0  # both empty — indistinguishable

    # Description similarity (truncated to 200 chars)
    desc_a = a["description"][:200].lower()
    desc_b = b["description"][:200].lower()
    desc_sim = SequenceMatcher(None, desc_a, desc_b).ratio()

    # Severity match
    sev_sim = 1.0 if a["severity"] == b["severity"] else 0.0

    return 0.35 * title_sim + 0.25 * cwe_sim + 0.15 * host_sim + 0.15 * desc_sim + 0.10 * sev_sim


def _threshold_for_pair(
    a: dict[str, Any],
    b: dict[str, Any],
    sev_thresholds: dict[str, float],
    default_threshold: float,
) -> float:
    """Return threshold for a pair — use the higher-severity finding's threshold."""
    rank_a = _SEVERITY_RANK.get(a["severity"], 0)
    rank_b = _SEVERITY_RANK.get(b["severity"], 0)
    max_sev = a["severity"] if rank_a >= rank_b else b["severity"]
    return sev_thresholds.get(max_sev, default_threshold)


def _blocking_candidates(extracted: list[dict[str, Any]]) -> set[tuple[int, int]]:
    """Tier 1: deterministic blocking on structured fields."""
    buckets: dict[str, list[int]] = defaultdict(list)
    max_bucket = 1000

    for i, f in enumerate(extracted):
        # CWE key
        if f["cwe_id"] is not None:
            buckets[f"cwe:{f['cwe_id']}"].append(i)

        # Title prefix (first 5 tokens)
        tokens = f["title_lower"].split()[:5]
        if tokens:
            buckets[f"title5:{' '.join(tokens)}"].append(i)

        # Exact title
        buckets[f"exact:{f['title_lower']}"].append(i)

        # Host+CWE combos
        if f["cwe_id"] is not None:
            for host in f["affected_hosts"]:
                buckets[f"hostcwe:{host}|{f['cwe_id']}"].append(i)

        # Host+severity combos
        for host in f["affected_hosts"]:
            buckets[f"hostsev:{host}|{f['severity']}"].append(i)

    candidates: set[tuple[int, int]] = set()
    for members in buckets.values():
        if len(members) > max_bucket or len(members) < 2:
            continue
        for pos_a, idx_a in enumerate(members):
            for idx_b in members[pos_a + 1 :]:
                pair = (idx_a, idx_b) if idx_a < idx_b else (idx_b, idx_a)
                candidates.add(pair)

    return candidates


def python_correlate_findings(
    findings: list[dict[str, Any]],
    *,
    threshold: float = 0.8,
    severity_thresholds: dict[str, float] | None = None,
) -> list[tuple[int, int, float]]:
    """Find pairs of correlated findings above the similarity threshold.

    Uses Tier 1 blocking for n >= 100, brute-force for smaller sets.

    Returns list of (index_a, index_b, similarity_score) tuples, ordered
    so index_a < index_b.
    """
    sev_map = severity_thresholds or {}

    extracted = [_extract(f) for f in findings]
    n = len(extracted)

    if n < 2:
        return []

    if n < 100:
        # Brute-force for small sets
        result: list[tuple[int, int, float]] = []
        for i in range(n):
            for j in range(i + 1, n):
                score = _score_pair(extracted[i], extracted[j])
                thr = _threshold_for_pair(extracted[i], extracted[j], sev_map, threshold)
                if score >= thr:
                    result.append((i, j, score))
        return result

    # Tier 1: blocking
    candidates = _blocking_candidates(extracted)

    # Tier 3: score candidates
    result = []
    for i, j in candidates:
        score = _score_pair(extracted[i], extracted[j])
        thr = _threshold_for_pair(extracted[i], extracted[j], sev_map, threshold)
        if score >= thr:
            result.append((i, j, score))

    return result
