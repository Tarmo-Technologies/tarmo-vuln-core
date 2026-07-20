"""NVD CVE enrichment — queries the NVD REST API v2 to populate CVSS, CWE, and description."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

from tarmo_vuln_core.models import Finding

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "tarmo-vuln-core" / "nvd"
_CVE_PATTERN_PREFIX = "CVE-"


def _cache_path(cve_id: str, cache_dir: Path) -> Path:
    return cache_dir / f"{cve_id}.json"


def _fetch_nvd(cve_id: str, api_key: str | None) -> dict | None:  # type: ignore[type-arg]
    """Fetch a single CVE from NVD REST API v2. Returns parsed JSON or None on error."""
    url = f"{_NVD_API_BASE}?cveId={cve_id}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None


def _load_cached(cve_id: str, cache_dir: Path) -> dict | None:  # type: ignore[type-arg]
    path = _cache_path(cve_id, cache_dir)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_cache(cve_id: str, data: dict, cache_dir: Path) -> None:  # type: ignore[type-arg]
    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        _cache_path(cve_id, cache_dir).write_text(json.dumps(data), encoding="utf-8")
    except OSError as exc:
        logger.warning("NVD cache write failed for %s: %s", cve_id, exc)


def _parse_nvd_response(data: dict) -> dict:  # type: ignore[type-arg]
    """Extract CVSS score/vector, CWE ID, and English description from NVD response."""
    result: dict = {}  # type: ignore[type-arg]
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return result

    cve_data = vulnerabilities[0].get("cve", {})

    # English description
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "")
            break

    # CWE ID (first entry)
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                try:
                    result["cwe_id"] = int(cwe_val[4:])
                    break
                except ValueError:
                    pass
        if "cwe_id" in result:
            break

    # CVSS scores — prefer 4.0, then 3.1, 3.0, 2.0
    _METRIC_VERSION_MAP = {
        "cvssMetricV40": "4.0",
        "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0",
        "cvssMetricV2": "2.0",
    }
    metrics = cve_data.get("metrics", {})
    for key, version in _METRIC_VERSION_MAP.items():
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if score is not None:
                result["cvss_score"] = float(score)
                result["cvss_version"] = version
            if vector:
                result["cvss_vector"] = vector
            break

    # Additionally, always capture v4.0 metrics separately when present
    v40_entries = metrics.get("cvssMetricV40", [])
    if v40_entries:
        v40_data = v40_entries[0].get("cvssData", {})
        v40_score = v40_data.get("baseScore")
        v40_vector = v40_data.get("vectorString")
        if v40_score is not None:
            result["cvss_v4_score"] = float(v40_score)
        if v40_vector:
            result["cvss_v4_vector"] = v40_vector

    return result


def enrich_finding_from_nvd(
    finding: Finding,
    api_key: str | None = None,
    cache_dir: Path | None = None,
    _rate_delay: float = 0.0,
) -> Finding:
    """Enrich a single finding with NVD data if it has a CVE raw_ref.

    Local finding fields always take precedence over NVD data.
    Network errors are silently swallowed — the original finding is returned.

    Args:
        finding: Finding to enrich.
        api_key: Optional NVD API key (from NVD_API_KEY env var or engagement config).
        cache_dir: Directory for caching NVD responses. Defaults to ~/.cache/tarmo-vuln-core/nvd/.
        _rate_delay: Seconds to sleep after a live fetch (for rate limiting, injected in tests).

    Returns:
        Enriched Finding (or original if no CVE ref or network failure).
    """
    if not finding.raw_ref or not finding.raw_ref.upper().startswith(_CVE_PATTERN_PREFIX):
        return finding

    cve_id = finding.raw_ref.upper()
    resolved_cache = cache_dir or _DEFAULT_CACHE_DIR

    data = _load_cached(cve_id, resolved_cache)
    if data is None:
        data = _fetch_nvd(cve_id, api_key)
        if data is None:
            return finding
        _save_cache(cve_id, data, resolved_cache)
        if _rate_delay > 0:
            time.sleep(_rate_delay)

    parsed = _parse_nvd_response(data)
    if not parsed:
        return finding

    updates: dict = {}  # type: ignore[type-arg]
    # Only fill fields that are unset on the finding
    if finding.cvss_score is None and "cvss_score" in parsed:
        updates["cvss_score"] = parsed["cvss_score"]
    if finding.cvss_vector is None and "cvss_vector" in parsed:
        updates["cvss_vector"] = parsed["cvss_vector"]
    if finding.cvss_version is None and "cvss_version" in parsed:
        updates["cvss_version"] = parsed["cvss_version"]
    if finding.cvss_v4_score is None and "cvss_v4_score" in parsed:
        updates["cvss_v4_score"] = parsed["cvss_v4_score"]
    if finding.cvss_v4_vector is None and "cvss_v4_vector" in parsed:
        updates["cvss_v4_vector"] = parsed["cvss_v4_vector"]
    if finding.cwe_id is None and "cwe_id" in parsed:
        updates["cwe_id"] = parsed["cwe_id"]
    # Description only for non-manual findings
    if finding.source_tool != "manual" and "description" in parsed and parsed["description"]:
        updates["description"] = parsed["description"]

    if not updates:
        return finding

    logger.info("NVD enriched %s (%s)", finding.id, cve_id)
    return finding.model_copy(update=updates)


def enrich_findings_from_nvd(
    findings: list[Finding],
    api_key: str | None = None,
    cache_dir: Path | None = None,
) -> list[Finding]:
    """Enrich a list of findings from NVD. Rate-limits requests automatically.

    Applies a delay of 6s between live fetches (or 0.6s with api_key).

    Args:
        findings: Findings to enrich.
        api_key: Optional NVD API key.
        cache_dir: Cache directory for NVD responses.

    Returns:
        List of enriched findings (order preserved).
    """
    delay = 0.6 if api_key else 6.0
    return [
        enrich_finding_from_nvd(f, api_key=api_key, cache_dir=cache_dir, _rate_delay=delay)
        for f in findings
    ]
