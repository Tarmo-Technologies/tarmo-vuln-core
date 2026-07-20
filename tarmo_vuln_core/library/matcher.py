"""Finding matcher — enriches Finding objects from the library."""

from __future__ import annotations

from tarmo_vuln_core.models import Finding


def build_alias_index(library: dict[str, dict]) -> dict[str, str]:  # type: ignore[type-arg]
    """Build a reverse-lookup index mapping alias keys to canonical library IDs.

    Keys are of the form ``"nessus_plugin:42873"`` or ``"cve:CVE-2016-2183"``.

    Args:
        library: Dict mapping canonical id -> finding data, from load_library().

    Returns:
        Dict mapping alias key -> canonical library id.
    """
    index: dict[str, str] = {}
    for canonical_id, entry in library.items():
        aliases = entry.get("aliases") or {}
        for plugin_id in aliases.get("nessus_plugin") or []:
            index[f"nessus_plugin:{plugin_id}"] = canonical_id
        for cve in aliases.get("cve") or []:
            if cve:
                index[f"cve:{cve}"] = canonical_id
        for rule_id in aliases.get("semgrep_rule") or []:
            if rule_id:
                index[f"semgrep_rule:{rule_id}"] = canonical_id
        for test_id in aliases.get("bandit_test") or []:
            if test_id:
                index[f"bandit_test:{test_id}"] = canonical_id
        for rule_id in aliases.get("gitleaks_rule") or []:
            if rule_id:
                index[f"gitleaks_rule:{rule_id}"] = canonical_id
        for detector in aliases.get("trufflehog_detector") or []:
            if detector:
                index[f"trufflehog_detector:{detector}"] = canonical_id
        for cwe_id in aliases.get("cwe") or []:
            if cwe_id:
                index[f"cwe:{cwe_id}"] = canonical_id
    return index


def match_finding(
    finding: Finding,
    library: dict[str, dict],  # type: ignore[type-arg]
    alias_index: dict[str, str] | None = None,
) -> Finding:
    """Enrich a Finding with data from the library, if a match exists.

    Lookup order:
    1. Direct ``library[finding.id]``
    2. If ``finding.id`` starts with ``"nessus-plugin-"``, extract numeric part
       and look up as ``nessus_plugin:{n}`` in the alias index.
    3. If ``finding.raw_ref`` starts with ``"CVE-"``, look up as ``cve:{raw_ref}``.
    4. If ``finding.raw_ref`` is purely numeric, look up as ``nessus_plugin:{raw_ref}``.
    5. If ``finding.source_tool == "gitleaks"``, look up as ``gitleaks_rule:{raw_ref}``.
    6. If ``finding.source_tool == "trufflehog"``, look up ``trufflehog_detector:{raw_ref}``.
    7. If ``finding.source_tool == "bandit"``, look up as ``bandit_test:{raw_ref}``.
    8. If ``finding.source_tool == "semgrep"``, look up as ``semgrep_rule:{raw_ref}``.
    9. If ``finding.cwe_id`` is set, look up as ``cwe:{cwe_id}`` (last resort).

    Enrichment rules (pentester overrides always take precedence):
    - ``cwe_id``, ``cvss_score``, ``cvss_vector``, ``owasp_id``: filled only when
      ``None`` on the finding.
    - ``steps``: filled only when empty on the finding.
    - ``description``, ``impact``, ``remediation``: filled only when
      ``source_tool != "manual"`` (automated ingestors produce generic defaults;
      library versions are curated). Manual findings keep human-written text.
    - ``id``: remapped to the canonical library id when matched via alias.

    Args:
        finding: The Finding to enrich.
        library: Dict mapping canonical id -> finding data, from load_library().
        alias_index: Optional pre-built alias index from build_alias_index().
                     Built on-the-fly if not provided.

    Returns:
        The enriched Finding. If no match, returns the original finding unchanged.
    """
    if alias_index is None:
        alias_index = build_alias_index(library)

    # 1. Direct id match
    entry = library.get(finding.id)
    canonical_id = finding.id

    # 2. Nessus plugin id encoded in finding.id
    if entry is None and finding.id.startswith("nessus-plugin-"):
        numeric = finding.id[len("nessus-plugin-") :]
        key = f"nessus_plugin:{numeric}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 3. CVE in raw_ref
    if entry is None and finding.raw_ref and finding.raw_ref.upper().startswith("CVE-"):
        key = f"cve:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 4. Numeric raw_ref → nessus plugin id
    if entry is None and finding.raw_ref and finding.raw_ref.isdigit():
        key = f"nessus_plugin:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 5. Gitleaks finding → gitleaks_rule:{raw_ref}
    if entry is None and finding.source_tool == "gitleaks" and finding.raw_ref:
        key = f"gitleaks_rule:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 6. TruffleHog finding → trufflehog_detector:{raw_ref}
    if entry is None and finding.source_tool == "trufflehog" and finding.raw_ref:
        key = f"trufflehog_detector:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 7. Bandit finding → bandit_test:{raw_ref}
    if entry is None and finding.source_tool == "bandit" and finding.raw_ref:
        key = f"bandit_test:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 8. Semgrep finding → semgrep_rule:{raw_ref}
    if entry is None and finding.source_tool == "semgrep" and finding.raw_ref:
        key = f"semgrep_rule:{finding.raw_ref}"
        canonical_id = alias_index.get(key, finding.id)
        entry = library.get(canonical_id)

    # 9. CWE ID on finding → cwe:{id} alias (last resort — enrich only, do NOT
    #    remap ID. CWE is a category-level match, too broad to change identity.
    #    Tool-specific matches above take precedence.)
    if entry is None and finding.cwe_id is not None:
        key = f"cwe:{finding.cwe_id}"
        cwe_canonical = alias_index.get(key)
        if cwe_canonical:
            entry = library.get(cwe_canonical)
            # Keep original finding.id — don't set canonical_id

    if entry is None:
        return finding

    updates: dict = {}  # type: ignore[type-arg]

    # Remap id to canonical when matched via alias
    if canonical_id != finding.id:
        updates["id"] = canonical_id

    # Numeric / classification fields — only fill when unset
    if finding.cwe_id is None and entry.get("cwe_id") is not None:
        updates["cwe_id"] = entry["cwe_id"]

    if finding.cvss_score is None and entry.get("cvss_score") is not None:
        updates["cvss_score"] = entry["cvss_score"]

    if finding.cvss_vector is None and entry.get("cvss_vector") is not None:
        updates["cvss_vector"] = entry["cvss_vector"]

    if finding.owasp_id is None and entry.get("owasp_id") is not None:
        updates["owasp_id"] = entry["owasp_id"]

    if finding.cvss_version is None and entry.get("cvss_version") is not None:
        updates["cvss_version"] = entry["cvss_version"]

    # Steps — fill only when empty
    if not finding.steps and entry.get("steps"):
        updates["steps"] = list(entry["steps"])

    # Compliance refs — accumulate (library adds to any already on the finding)
    if entry.get("compliance_refs"):
        merged = list(dict.fromkeys(finding.compliance_refs + list(entry["compliance_refs"])))
        if merged != finding.compliance_refs:
            updates["compliance_refs"] = merged

    # ATT&CK fields — accumulate from library when present
    if entry.get("attack_ids"):
        merged_attack = list(dict.fromkeys(finding.attack_ids + list(entry["attack_ids"])))
        if merged_attack != finding.attack_ids:
            updates["attack_ids"] = merged_attack
    if entry.get("attack_tactics"):
        merged_tactics = list(dict.fromkeys(finding.attack_tactics + list(entry["attack_tactics"])))
        if merged_tactics != finding.attack_tactics:
            updates["attack_tactics"] = merged_tactics

    # Methodology items — fill only when empty on the finding
    if not finding.methodology_items and entry.get("methodology_items"):
        updates["methodology_items"] = list(entry["methodology_items"])

    # Prose fields — fill only when the field is empty and source is not manual.
    # Human-written prose on any finding takes precedence over library defaults;
    # automated tools that produce no prose get library descriptions as fallback.
    if finding.source_tool != "manual":
        if not finding.description and entry.get("description"):
            updates["description"] = entry["description"].strip()
        if not finding.impact and entry.get("impact"):
            updates["impact"] = entry["impact"].strip()
        if not finding.remediation and entry.get("remediation"):
            updates["remediation"] = entry["remediation"].strip()

    if not updates:
        return finding

    return finding.model_copy(update=updates)
