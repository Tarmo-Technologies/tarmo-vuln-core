"""Tests for tarmo_vuln_core.library — loader, matcher, checker, import_library."""

from __future__ import annotations

from pathlib import Path

import yaml

from tarmo_vuln_core.models import Evidence, EvidenceType, Finding, Severity

# ── loader ───────────────────────────────────────────────────────────────────


class TestLoadLibrary:
    def test_loads_yaml_files(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.library.loader import load_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "web.yaml").write_text(
            yaml.dump(
                [
                    {"id": "xss-reflected", "title": "Reflected XSS", "severity": "HIGH"},
                    {"id": "sqli", "title": "SQL Injection", "severity": "CRITICAL"},
                ]
            )
        )
        result = load_library(lib_dir)
        assert len(result) == 2
        assert result["xss-reflected"]["title"] == "Reflected XSS"
        assert result["sqli"]["severity"] == "CRITICAL"

    def test_scope_types_filter(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.library.loader import load_library

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "web.yaml").write_text(yaml.dump([{"id": "xss", "title": "XSS"}]))
        (lib_dir / "network.yaml").write_text(yaml.dump([{"id": "smb", "title": "SMB"}]))
        result = load_library(lib_dir, scope_types=["web"])
        assert "xss" in result
        assert "smb" not in result

    def test_later_dir_overrides(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.library.loader import load_library

        dir1 = tmp_path / "d1"
        dir1.mkdir()
        dir2 = tmp_path / "d2"
        dir2.mkdir()
        (dir1 / "web.yaml").write_text(yaml.dump([{"id": "xss", "title": "Old"}]))
        (dir2 / "web.yaml").write_text(yaml.dump([{"id": "xss", "title": "New"}]))
        result = load_library(dir1, dir2)
        assert result["xss"]["title"] == "New"

    def test_nonexistent_dir_skipped(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.library.loader import load_library

        result = load_library(tmp_path / "nonexistent")
        assert result == {}

    def test_default_library_dir_exists(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR

        assert DEFAULT_LIBRARY_DIR.exists()

    def test_bundled_library_loads(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR)
        assert len(result) > 10
        # Spot check a known entry
        assert "xss-reflected" in result or "sql-injection" in result

    def test_sast_library_loads(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["sast"])
        assert len(result) == 14
        assert "sql-injection-source" in result
        assert result["sql-injection-source"]["cwe_id"] == 89
        assert result["sql-injection-source"]["severity"] == "CRITICAL"

    def test_sast_entries_have_required_fields(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["sast"])
        for entry_id, entry in result.items():
            assert "title" in entry, f"{entry_id} missing title"
            assert "severity" in entry, f"{entry_id} missing severity"
            assert "cwe_id" in entry, f"{entry_id} missing cwe_id"
            assert "description" in entry, f"{entry_id} missing description"
            assert "steps" in entry, f"{entry_id} missing steps"
            assert "aliases" in entry, f"{entry_id} missing aliases"
            assert len(entry["steps"]) >= 3, f"{entry_id} has too few steps"

    def test_sast_entries_have_semgrep_or_bandit_aliases(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["sast"])
        has_aliases = 0
        for entry in result.values():
            aliases = entry.get("aliases", {})
            if aliases.get("semgrep_rule") or aliases.get("bandit_test"):
                has_aliases += 1
        # At least 10 of 14 entries should have SAST tool aliases
        assert has_aliases >= 10

    def test_secrets_library_loads(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["secrets"])
        assert len(result) == 10
        assert "hardcoded-api-key" in result
        assert result["hardcoded-api-key"]["cwe_id"] == 798

    def test_secrets_entries_have_required_fields(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["secrets"])
        for entry_id, entry in result.items():
            assert "title" in entry, f"{entry_id} missing title"
            assert "severity" in entry, f"{entry_id} missing severity"
            assert "cwe_id" in entry, f"{entry_id} missing cwe_id"
            assert "description" in entry, f"{entry_id} missing description"
            assert "steps" in entry, f"{entry_id} missing steps"
            assert len(entry["steps"]) >= 3, f"{entry_id} has too few steps"

    def test_secrets_entries_have_gitleaks_or_trufflehog_aliases(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        result = load_library(DEFAULT_LIBRARY_DIR, scope_types=["secrets"])
        has_aliases = 0
        for entry in result.values():
            aliases = entry.get("aliases", {})
            if aliases.get("gitleaks_rule") or aliases.get("trufflehog_detector"):
                has_aliases += 1
        # At least 7 of 10 entries should have secret scanning tool aliases
        assert has_aliases >= 7


# ── matcher ──────────────────────────────────────────────────────────────────


def _make_finding(**overrides) -> Finding:
    defaults = {
        "id": "test-finding",
        "title": "Test Finding",
        "severity": Severity.MEDIUM,
        "description": "A test finding.",
        "impact": "Test impact.",
        "remediation": "Test remediation.",
        "source_tool": "nessus",
        "affected_hosts": ["10.0.0.1"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestBuildAliasIndex:
    def test_nessus_plugin_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "ssl-weak-cipher": {
                "id": "ssl-weak-cipher",
                "aliases": {"nessus_plugin": [42873, 65821]},
            }
        }
        idx = build_alias_index(library)
        assert idx["nessus_plugin:42873"] == "ssl-weak-cipher"
        assert idx["nessus_plugin:65821"] == "ssl-weak-cipher"

    def test_cve_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "sweet32": {
                "id": "sweet32",
                "aliases": {"cve": ["CVE-2016-2183"]},
            }
        }
        idx = build_alias_index(library)
        assert idx["cve:CVE-2016-2183"] == "sweet32"

    def test_semgrep_rule_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "sql-injection-source": {
                "aliases": {"semgrep_rule": ["python.lang.security.audit.formatted-sql-query"]},
            }
        }
        idx = build_alias_index(library)
        assert (
            idx["semgrep_rule:python.lang.security.audit.formatted-sql-query"]
            == "sql-injection-source"
        )

    def test_bandit_test_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "sql-injection-source": {
                "aliases": {"bandit_test": ["B608"]},
            }
        }
        idx = build_alias_index(library)
        assert idx["bandit_test:B608"] == "sql-injection-source"

    def test_gitleaks_rule_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "hardcoded-api-key": {
                "aliases": {"gitleaks_rule": ["generic-api-key"]},
            }
        }
        idx = build_alias_index(library)
        assert idx["gitleaks_rule:generic-api-key"] == "hardcoded-api-key"

    def test_trufflehog_detector_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "hardcoded-api-key": {
                "aliases": {"trufflehog_detector": ["AWS"]},
            }
        }
        idx = build_alias_index(library)
        assert idx["trufflehog_detector:AWS"] == "hardcoded-api-key"

    def test_cwe_alias(self) -> None:
        from tarmo_vuln_core.library.matcher import build_alias_index

        library = {
            "sql-injection-source": {
                "aliases": {"cwe": [89]},
            }
        }
        idx = build_alias_index(library)
        assert idx["cwe:89"] == "sql-injection-source"


class TestMatchFinding:
    def test_direct_id_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "ssl-weak-cipher": {
                "cwe_id": 326,
                "cvss_score": 5.3,
                "description": "Library desc.",
            }
        }
        f = _make_finding(id="ssl-weak-cipher", cwe_id=None, cvss_score=None)
        enriched = match_finding(f, library)
        assert enriched.cwe_id == 326
        assert enriched.cvss_score == 5.3

    def test_nessus_plugin_alias_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "ssl-weak-cipher": {
                "id": "ssl-weak-cipher",
                "aliases": {"nessus_plugin": [42873]},
                "cwe_id": 326,
            }
        }
        f = _make_finding(id="nessus-plugin-42873", cwe_id=None)
        enriched = match_finding(f, library)
        assert enriched.id == "ssl-weak-cipher"
        assert enriched.cwe_id == 326

    def test_cve_raw_ref_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "sweet32": {
                "id": "sweet32",
                "aliases": {"cve": ["CVE-2016-2183"]},
                "cvss_score": 7.5,
            }
        }
        f = _make_finding(raw_ref="CVE-2016-2183", cvss_score=None)
        enriched = match_finding(f, library)
        assert enriched.cvss_score == 7.5

    def test_no_match_returns_original(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        f = _make_finding(id="unknown-vuln")
        enriched = match_finding(f, {})
        assert enriched is f

    def test_manual_source_preserves_prose(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {"xss": {"description": "Library XSS desc", "impact": "Library impact"}}
        f = _make_finding(id="xss", source_tool="manual", description="My desc", impact="My impact")
        enriched = match_finding(f, library)
        assert enriched.description == "My desc"
        assert enriched.impact == "My impact"

    def test_non_manual_with_existing_prose_preserved(self) -> None:
        """Prose already on a non-manual finding must not be overwritten by the library.

        Burp/Nessus/etc. findings ingested via a manual YAML have human-written
        descriptions. The library should fill prose only when the field is empty,
        not clobber existing content just because source_tool != 'manual'.
        """
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "xss-source": {
                "aliases": {"cwe": [79]},
                "description": "Static analysis identified template code.",
                "impact": "Generic library impact.",
                "remediation": "Apply context-aware output encoding.",
                "steps": ["Step 1 from library"],
            }
        }
        alias_index = {"cwe:79": "xss-source"}
        human_desc = "The search bar at /#/search reflects <iframe> payloads into the DOM."
        human_impact = "Session hijacking via token theft from authenticated victims."
        human_remediation = "Use Angular DomSanitizer and set a strict CSP header."
        f = _make_finding(
            id="xss-dom-search",
            source_tool="burp",
            cwe_id=79,
            description=human_desc,
            impact=human_impact,
            remediation=human_remediation,
            steps=[],
        )
        enriched = match_finding(f, library, alias_index)
        assert enriched.description == human_desc, (
            "Library prose must not overwrite non-empty description on a burp finding"
        )
        assert enriched.impact == human_impact, (
            "Library prose must not overwrite non-empty impact on a burp finding"
        )
        assert enriched.remediation == human_remediation, (
            "Library prose must not overwrite non-empty remediation on a burp finding"
        )
        # Steps were empty on the finding — library fill is acceptable
        assert enriched.steps == ["Step 1 from library"]

    def test_empty_prose_on_non_manual_filled_from_library(self) -> None:
        """Library prose should fill empty description/impact/remediation for non-manual tools."""
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "xss-source": {
                "aliases": {"cwe": [79]},
                "description": "Static analysis identified template code.",
                "impact": "Attacker can execute arbitrary JS.",
                "remediation": "Apply output encoding.",
            }
        }
        alias_index = {"cwe:79": "xss-source"}
        f = _make_finding(
            id="nikto-xss-001",
            source_tool="nikto",
            cwe_id=79,
            description="",
            impact="",
            remediation="",
        )
        enriched = match_finding(f, library, alias_index)
        assert enriched.description == "Static analysis identified template code."
        assert enriched.impact == "Attacker can execute arbitrary JS."
        assert enriched.remediation == "Apply output encoding."

    def test_existing_fields_not_overwritten(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {"test-finding": {"cwe_id": 999, "cvss_score": 9.0}}
        f = _make_finding(cwe_id=123, cvss_score=5.0)
        enriched = match_finding(f, library)
        assert enriched.cwe_id == 123
        assert enriched.cvss_score == 5.0

    def test_compliance_refs_accumulated(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {"test-finding": {"compliance_refs": ["PCI DSS 6.5.1"]}}
        f = _make_finding(compliance_refs=["ISO 27001 A.14"])
        enriched = match_finding(f, library)
        assert "ISO 27001 A.14" in enriched.compliance_refs
        assert "PCI DSS 6.5.1" in enriched.compliance_refs

    def test_cwe_id_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "sql-injection-source": {
                "aliases": {"cwe": [89]},
                "cvss_score": 9.3,
                "steps": ["Step 1", "Step 2"],
            }
        }
        f = _make_finding(cwe_id=89, cvss_score=None, steps=[])
        enriched = match_finding(f, library)
        assert enriched.cvss_score == 9.3
        assert enriched.steps == ["Step 1", "Step 2"]

    def test_bandit_source_tool_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "sql-injection-source": {
                "aliases": {"bandit_test": ["B608"]},
                "cvss_score": 9.3,
                "description": "Library SQL injection desc.",
            }
        }
        f = _make_finding(
            id="bandit-b608-login-py-l42",
            source_tool="bandit",
            raw_ref="B608",
            cvss_score=None,
        )
        enriched = match_finding(f, library)
        assert enriched.id == "sql-injection-source"
        assert enriched.cvss_score == 9.3

    def test_semgrep_source_tool_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "sql-injection-source": {
                "aliases": {"semgrep_rule": ["python.lang.security.audit.formatted-sql-query"]},
                "cvss_score": 9.3,
            }
        }
        f = _make_finding(
            id="semgrep-formatted-sql-query",
            source_tool="semgrep",
            raw_ref="python.lang.security.audit.formatted-sql-query",
            cvss_score=None,
        )
        enriched = match_finding(f, library)
        assert enriched.id == "sql-injection-source"
        assert enriched.cvss_score == 9.3

    def test_gitleaks_source_tool_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "hardcoded-api-key": {
                "aliases": {"gitleaks_rule": ["generic-api-key"]},
                "cvss_score": 8.2,
            }
        }
        f = _make_finding(
            id="gitleaks-generic-api-key-1",
            source_tool="gitleaks",
            raw_ref="generic-api-key",
            cvss_score=None,
        )
        enriched = match_finding(f, library)
        assert enriched.id == "hardcoded-api-key"
        assert enriched.cvss_score == 8.2

    def test_trufflehog_source_tool_match(self) -> None:
        from tarmo_vuln_core.library.matcher import match_finding

        library = {
            "exposed-cloud-credentials": {
                "aliases": {"trufflehog_detector": ["AWS"]},
                "cvss_score": 9.3,
            }
        }
        f = _make_finding(
            id="trufflehog-aws-1",
            source_tool="trufflehog",
            raw_ref="AWS",
            cvss_score=None,
        )
        enriched = match_finding(f, library)
        assert enriched.id == "exposed-cloud-credentials"
        assert enriched.cvss_score == 9.3

    def test_integration_bandit_cwe89_matches_sast_yaml(self) -> None:
        """Integration test: Bandit finding with CWE-89 matches sast.yaml entry."""
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library
        from tarmo_vuln_core.library.matcher import match_finding

        library = load_library(DEFAULT_LIBRARY_DIR)
        f = _make_finding(
            id="bandit-b608-app-py-l10",
            source_tool="bandit",
            raw_ref="B608",
            cwe_id=None,
            cvss_score=None,
            steps=[],
        )
        enriched = match_finding(f, library)
        assert enriched.id == "sql-injection-source"
        assert enriched.cwe_id == 89
        assert enriched.cvss_score == 9.3
        assert len(enriched.steps) > 0


# ── checker ──────────────────────────────────────────────────────────────────


class TestChecker:
    def test_complete_finding(self) -> None:
        from tarmo_vuln_core.library.checker import check_finding

        f = _make_finding()
        result = check_finding(f)
        assert result.is_complete
        assert result.finding_id == "test-finding"

    def test_missing_description(self) -> None:
        from tarmo_vuln_core.library.checker import check_finding

        f = _make_finding(description="  ")
        result = check_finding(f)
        assert not result.is_complete
        assert any("description" in m for m in result.missing)

    def test_critical_requires_evidence_and_cvss(self) -> None:
        from tarmo_vuln_core.library.checker import check_finding

        f = _make_finding(severity=Severity.CRITICAL, evidence=[], cvss_score=None)
        result = check_finding(f)
        assert not result.is_complete
        assert any("evidence" in m for m in result.missing)
        assert any("cvss" in m for m in result.missing)

    def test_high_with_evidence_and_cvss_is_complete(self) -> None:
        from tarmo_vuln_core.library.checker import check_finding

        f = _make_finding(
            severity=Severity.HIGH,
            evidence=[Evidence(filename="shot.png", type=EvidenceType.SCREENSHOT)],
            cvss_score=7.5,
        )
        result = check_finding(f)
        assert result.is_complete

    def test_check_findings_batch(self) -> None:
        from tarmo_vuln_core.library.checker import check_findings

        findings = [_make_finding(), _make_finding(description="")]
        results = check_findings(findings)
        assert len(results) == 2
        assert results[0].is_complete
        assert not results[1].is_complete

    def test_potential_finding_checked_like_verified(self) -> None:
        """POTENTIAL findings are checked for completeness identically to VERIFIED."""
        from tarmo_vuln_core.library.checker import check_finding
        from tarmo_vuln_core.models import FindingStatus

        # Complete POTENTIAL finding passes the gate
        complete_potential = _make_finding(
            severity=Severity.CRITICAL,
            status=FindingStatus.POTENTIAL,
            evidence=[Evidence(filename="shot.png", type=EvidenceType.SCREENSHOT)],
            cvss_score=8.5,
            affected_hosts=["10.0.0.1"],
        )
        result = check_finding(complete_potential)
        assert result.is_complete

        # Incomplete POTENTIAL finding fails the gate (same as VERIFIED)
        incomplete_potential = _make_finding(
            severity=Severity.CRITICAL,
            status=FindingStatus.POTENTIAL,
            evidence=[],
            cvss_score=None,
            affected_hosts=[],
        )
        result = check_finding(incomplete_potential)
        assert not result.is_complete
        assert any("evidence" in m for m in result.missing)
        assert any("cvss" in m for m in result.missing)
        assert any("affected_hosts" in m for m in result.missing)
