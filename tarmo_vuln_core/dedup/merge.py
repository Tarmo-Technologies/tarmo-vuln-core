"""Finding and instance merge logic — pure Finding/Instance operations with no DB dependency.

Extracted from pentest-scribe's db.py for shared use across downstream consumers.
"""

from __future__ import annotations

from tarmo_vuln_core.models import Finding, Instance


def merge_instances(old: list[Instance], new: list[Instance]) -> list[Instance]:
    """Union instances by (host, port, path); old instance state wins on conflict.

    Preserves per-instance ``status``, ``notes``, and ``verified_at`` from the
    existing record when the same (host, port, path) key is re-ingested.
    Genuinely new locations from ``new`` are appended.
    """
    key = lambda i: (i.host, i.port, i.path or "")  # noqa: E731
    old_map = {key(i): i for i in old}  # type: ignore[no-untyped-call]
    result = list(old_map.values())
    for inst in new:
        k = key(inst)  # type: ignore[no-untyped-call]
        if k not in old_map:
            result.append(inst)
    return result


def merge_findings(old: Finding, new: Finding) -> Finding:
    """Return a new Finding that is the merge of old (existing) and new (incoming).

    Same-id re-ingest (old.id == new.id): takes ``new`` as base so updated
    title/description/evidence/remediation are picked up; only assessor lifecycle
    fields are preserved from ``old``.

    Cross-tool dedup (old.id != new.id): takes ``old`` as base (the canonical
    record), merging host lists, source tool lists, and keeping the higher CVSS.
    """
    merged_hosts = list(dict.fromkeys(old.affected_hosts + new.affected_hosts))
    merged_tools = list(dict.fromkeys((old.source_tools or [old.source_tool]) + [new.source_tool]))
    merged_instances = merge_instances(old.instances, new.instances)

    if old.cvss_score is None:
        cvss = new.cvss_score
        cvss_version = new.cvss_version
    elif new.cvss_score is None or old.cvss_score >= new.cvss_score:
        cvss = old.cvss_score
        cvss_version = old.cvss_version
    else:
        cvss = new.cvss_score
        cvss_version = new.cvss_version

    # Assessor lifecycle fields are always preserved from the existing record
    assessor_fields = {
        "status": old.status,
        "remediated_at": old.remediated_at,
        "verified_at": old.verified_at,
        "notes": old.notes,
    }

    if old.id == new.id:
        # Same finding re-ingested: new wins for content, preserve assessor fields
        return new.model_copy(
            update={
                "affected_hosts": merged_hosts,
                "instances": merged_instances,
                "source_tools": merged_tools,
                "cvss_score": cvss,
                "cvss_version": cvss_version,
                **assessor_fields,
            }
        )
    # Cross-tool dedup: old wins for content, accumulate hosts/tools/cvss
    return old.model_copy(
        update={
            "affected_hosts": merged_hosts,
            "instances": merged_instances,
            "source_tools": merged_tools,
            "cvss_score": cvss,
            "cvss_version": cvss_version,
            **assessor_fields,
        }
    )
