"""Import finding library templates from DefectDojo or Ghostwriter APIs.

Both importers produce YAML files compatible with the library format.
Duplicate IDs (slugs of the title) are skipped with a warning so repeated
imports are safe.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from tarmo_vuln_core.utils import slugify as _slugify

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
    "none": "INFO",
}


def _normalise_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.lower(), "MEDIUM")


def _existing_ids(output_path: Path) -> set[str]:
    """Return the set of IDs already in *output_path* (if it exists)."""
    if not output_path.exists():
        return set()
    try:
        data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {entry.get("id", "") for entry in data if isinstance(entry, dict)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read existing library %s: %s", output_path, exc)
    return set()


def _append_entries(entries: list[dict], output_path: Path) -> None:  # type: ignore[type-arg]
    """Append *entries* to *output_path*, creating it if absent."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    new_text = yaml.dump(entries, default_flow_style=False, allow_unicode=True, sort_keys=False)
    with output_path.open("a", encoding="utf-8") as fh:
        if existing_text and not existing_text.endswith("\n"):
            fh.write("\n")
        fh.write("\n")
        fh.write(new_text)


def import_from_defectdojo(
    url: str,
    token: str,
    output_path: Path,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Import finding templates from a DefectDojo instance.

    Queries ``GET /api/v2/finding_templates/`` and converts each template
    to library YAML format.

    Args:
        url: Base URL of the DefectDojo instance, e.g. ``https://dojo.example.com``.
        token: DefectDojo API token.
        output_path: YAML file to append new entries to.
        dry_run: If True, print a plan without writing.

    Returns:
        Dict with keys ``new``, ``skipped``, ``failed``.
    """
    try:
        import json as _json
        import urllib.request as _req

        req = _req.Request(
            f"{url.rstrip('/')}/api/v2/finding_templates/?limit=500",
            headers={"Authorization": f"Token {token}", "Content-Type": "application/json"},
        )
        with _req.urlopen(req, timeout=30) as resp:  # nosec B310
            data = _json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"DefectDojo API call failed: {exc}") from exc

    templates: list[Any] = data.get("results", [])
    existing = _existing_ids(output_path)

    new_entries: list[dict] = []  # type: ignore[type-arg]
    stats = {"new": 0, "skipped": 0, "failed": 0}

    for tmpl in templates:
        try:
            title = tmpl.get("title", "").strip()
            if not title:
                stats["failed"] += 1
                continue
            slug = _slugify(title)
            if slug in existing:
                stats["skipped"] += 1
                continue

            entry: dict = {  # type: ignore[type-arg]
                "id": slug,
                "title": title,
                "severity": _normalise_severity(tmpl.get("severity", "medium")),
                "description": (tmpl.get("description") or "").strip() or "See reference.",
                "impact": (tmpl.get("impact") or "").strip() or "Impact not specified.",
                "remediation": (
                    (tmpl.get("mitigation") or "").strip() or "Remediation not specified."
                ),
            }
            if tmpl.get("cwe"):
                entry["cwe_id"] = int(tmpl["cwe"])
            if tmpl.get("cvssv3"):
                entry["cvss_vector"] = tmpl["cvssv3"]
            if tmpl.get("tags"):
                entry["tags"] = tmpl["tags"] if isinstance(tmpl["tags"], list) else [tmpl["tags"]]
            refs = []
            if tmpl.get("references"):
                refs = [r.strip() for r in tmpl["references"].splitlines() if r.strip()]
            if refs:
                entry["references"] = refs

            new_entries.append(entry)
            existing.add(slug)
            stats["new"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to convert DefectDojo template: %s", exc)
            stats["failed"] += 1

    if dry_run:
        for e in new_entries:
            print(f"  [new]  {e['id']}  ({e['severity']}): {e['title']}")
    elif new_entries:
        _append_entries(new_entries, output_path)

    return stats


def import_from_ghostwriter(
    url: str,
    token: str,
    output_path: Path,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Import finding templates from a Ghostwriter instance via GraphQL.

    Args:
        url: Base URL of the Ghostwriter instance.
        token: Ghostwriter API token.
        output_path: YAML file to append new entries to.
        dry_run: If True, print a plan without writing.

    Returns:
        Dict with keys ``new``, ``skipped``, ``failed``.
    """
    query = """
    query {
      findings {
        title
        severity { severity }
        description
        impact
        mitigation
        references
        findingType { findingType }
      }
    }
    """
    try:
        import json as _json
        import urllib.request as _req

        payload = _json.dumps({"query": query}).encode()
        req = _req.Request(
            f"{url.rstrip('/')}/api/",
            data=payload,
            headers={
                "Authorization": f"Token {token}",
                "Content-Type": "application/json",
            },
        )
        with _req.urlopen(req, timeout=30) as resp:  # nosec B310
            data = _json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Ghostwriter API call failed: {exc}") from exc

    findings: list[Any] = data.get("data", {}).get("findings", [])
    existing = _existing_ids(output_path)

    new_entries: list[dict] = []  # type: ignore[type-arg]
    stats = {"new": 0, "skipped": 0, "failed": 0}

    for tmpl in findings:
        try:
            title = tmpl.get("title", "").strip()
            if not title:
                stats["failed"] += 1
                continue
            slug = _slugify(title)
            if slug in existing:
                stats["skipped"] += 1
                continue

            sev_raw = ""
            if isinstance(tmpl.get("severity"), dict):
                sev_raw = tmpl["severity"].get("severity", "")

            entry: dict = {  # type: ignore[type-arg]
                "id": slug,
                "title": title,
                "severity": _normalise_severity(sev_raw or "medium"),
                "description": (tmpl.get("description") or "").strip() or "See reference.",
                "impact": (tmpl.get("impact") or "").strip() or "Impact not specified.",
                "remediation": (
                    (tmpl.get("mitigation") or "").strip() or "Remediation not specified."
                ),
            }
            refs = []
            if tmpl.get("references"):
                refs = [r.strip() for r in tmpl["references"].splitlines() if r.strip()]
            if refs:
                entry["references"] = refs

            new_entries.append(entry)
            existing.add(slug)
            stats["new"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to convert Ghostwriter finding: %s", exc)
            stats["failed"] += 1

    if dry_run:
        for e in new_entries:
            print(f"  [new]  {e['id']}  ({e['severity']}): {e['title']}")
    elif new_entries:
        _append_entries(new_entries, output_path)

    return stats
