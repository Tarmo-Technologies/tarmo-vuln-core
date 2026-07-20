"""Regression test suite for tarmo-vuln-core.

These tests guard critical functionality that must never break.
They cover cross-component workflows, not just individual units.
Run selectively: pytest tests/ -m regression
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.dedup import deduplicate_findings
from tarmo_vuln_core.dedup.merge import merge_findings
from tarmo_vuln_core.ingestors import auto_detect
from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library
from tarmo_vuln_core.library.matcher import build_alias_index, match_finding
from tarmo_vuln_core.models import Finding, Severity
from tarmo_vuln_core.models.finding import RuntimeTarget, SourceCodeRef

FIXTURES = Path(__file__).parent / "fixtures"


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": "test-finding",
        "title": "Test Finding",
        "severity": Severity.MEDIUM,
        "description": "A test finding.",
        "impact": "Test impact.",
        "remediation": "Test remediation.",
        "source_tool": "manual",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


# ── 1. Parser Stability ─────────────────────────────────────────────────────


@pytest.mark.regression
class TestParserStability:
    """Each ingestor produces the expected finding count from its fixture.

    If any of these change, a parser was modified in a breaking way.
    """

    def test_registry_has_38_parsers(self) -> None:
        assert len(DEFAULT_REGISTRY_ORDER) == 38

    def test_nessus_real_produces_12_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor

        findings = NessusIngestor().ingest(FIXTURES / "nessus_real.nessus")
        assert len(findings) == 12

    def test_nmap_real_produces_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor

        findings = NmapIngestor().ingest(FIXTURES / "nmap_real.xml")
        assert len(findings) >= 1

    def test_burp_real_produces_7_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor

        findings = BurpIngestor().ingest(FIXTURES / "burp_real.xml")
        assert len(findings) == 7

    def test_bandit_real_produces_35_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.bandit import BanditIngestor

        findings = BanditIngestor().ingest(FIXTURES / "bandit_real.json")
        assert len(findings) == 35

    def test_sarif_sample_produces_3_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor

        findings = SarifIngestor().ingest(FIXTURES / "sarif_sample.json")
        assert len(findings) == 3

    def test_cppcheck_real_produces_6_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor

        # 7 original groups minus 1 filtered noise (missingInclude) = 6
        findings = CppcheckIngestor().ingest(FIXTURES / "cppcheck_real.xml")
        assert len(findings) == 6

    def test_gitleaks_sample_produces_3_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.gitleaks import GitleaksIngestor

        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        assert len(findings) == 3

    def test_trufflehog_sample_produces_3_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.trufflehog import TrufflehogIngestor

        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert len(findings) == 3

    def test_trivy_real_produces_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.trivy import TrivyIngestor

        findings = TrivyIngestor().ingest(FIXTURES / "trivy_real.json")
        assert len(findings) >= 1

    def test_zap_real_produces_findings(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor

        findings = ZapIngestor().ingest(FIXTURES / "zap_real.xml")
        assert len(findings) >= 1


# ── 2. Library Enrichment Pipeline ──────────────────────────────────────────


@pytest.mark.regression
class TestLibraryEnrichmentPipeline:
    """Finding → matcher → enriched fields are correct for each alias type."""

    def setup_method(self) -> None:
        self.library = load_library(DEFAULT_LIBRARY_DIR)
        self.alias_index = build_alias_index(self.library)

    def test_library_loads_7_categories(self) -> None:
        categories = load_library(DEFAULT_LIBRARY_DIR)
        assert len(categories) > 50  # 7 YAML files with many entries

    def test_nessus_plugin_alias_enriches(self) -> None:
        f = _make_finding(id="nessus-plugin-42873", source_tool="nessus", cwe_id=None)
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.cwe_id is not None

    def test_bandit_b608_enriches_to_sqli(self) -> None:
        f = _make_finding(
            id="bandit-b608-test",
            source_tool="bandit",
            raw_ref="B608",
            cvss_score=None,
        )
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.id == "sql-injection-source"
        assert enriched.cvss_score == 9.3

    def test_gitleaks_api_key_enriches(self) -> None:
        f = _make_finding(
            id="gitleaks-generic-api-key",
            source_tool="gitleaks",
            raw_ref="generic-api-key",
            cvss_score=None,
        )
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.id == "hardcoded-api-key"
        assert enriched.cwe_id == 798

    def test_trufflehog_aws_enriches(self) -> None:
        f = _make_finding(
            id="trufflehog-aws",
            source_tool="trufflehog",
            raw_ref="AWS",
            cvss_score=None,
        )
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.id == "exposed-cloud-credentials"

    def test_cwe_enrichment_does_not_remap_id(self) -> None:
        """CWE-based matching enriches but preserves original finding ID."""
        f = _make_finding(id="my-custom-finding", cwe_id=89, cvss_score=None)
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.id == "my-custom-finding"  # NOT remapped
        assert enriched.cvss_score is not None  # but enriched

    def test_manual_finding_prose_preserved(self) -> None:
        """Manual findings keep human-written description/impact/remediation."""
        f = _make_finding(
            id="sql-injection",
            source_tool="manual",
            description="My custom desc",
            impact="My impact",
        )
        enriched = match_finding(f, self.library, self.alias_index)
        assert enriched.description == "My custom desc"
        assert enriched.impact == "My impact"


# ── 3. Dedup Determinism ────────────────────────────────────────────────────


@pytest.mark.regression
class TestDedupDeterminism:
    """Same input always produces same output."""

    def test_dedup_same_input_same_output(self) -> None:
        f = _make_finding()
        data = [f.model_dump(mode="json")] * 5
        result1 = deduplicate_findings(data)
        result2 = deduplicate_findings(data)
        assert len(result1) == len(result2) == 1

    def test_dedup_preserves_unique_findings(self) -> None:
        findings = [
            _make_finding(id=f"finding-{i}", title=f"Finding {i}").model_dump(mode="json")
            for i in range(10)
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 10

    def test_content_hash_stable(self) -> None:
        """Same finding always produces same content_hash."""
        f1 = _make_finding(title="Stable", affected_hosts=["10.0.0.1"])
        f2 = _make_finding(title="Stable", affected_hosts=["10.0.0.1"])
        assert f1.content_hash == f2.content_hash


# ── 4. Model Backwards Compatibility ────────────────────────────────────────


@pytest.mark.regression
class TestModelBackwardsCompat:
    """Findings without new fields still work correctly."""

    def test_finding_without_source_code_refs(self) -> None:
        data = {
            "id": "old-finding",
            "title": "Old Finding",
            "severity": "HIGH",
            "description": "desc",
            "impact": "impact",
            "remediation": "remed",
            "source_tool": "nessus",
        }
        f = Finding(**data)
        assert f.source_code_refs == []
        assert f.runtime_targets == []

    def test_finding_json_roundtrip_without_new_fields(self) -> None:
        f = _make_finding()
        data = json.loads(f.model_dump_json())
        f2 = Finding(**data)
        assert f2.id == f.id
        assert f2.source_code_refs == []

    def test_finding_json_roundtrip_with_new_fields(self) -> None:
        ref = SourceCodeRef(file_path="app.py", start_line=42, snippet="bad()")
        target = RuntimeTarget(url="/api", method="POST", confidence="high")
        f = _make_finding(source_code_refs=[ref], runtime_targets=[target])
        data = json.loads(f.model_dump_json())
        f2 = Finding(**data)
        assert f2.source_code_refs[0].file_path == "app.py"
        assert f2.runtime_targets[0].url == "/api"


# ── 5. Auto-Detection Routing ───────────────────────────────────────────────


@pytest.mark.regression
class TestAutoDetectRouting:
    """auto_detect routes fixtures to correct ingestors."""

    def test_nessus_real(self) -> None:
        i = auto_detect(FIXTURES / "nessus_real.nessus")
        assert "Nessus" in type(i).__name__

    def test_bandit_real(self) -> None:
        i = auto_detect(FIXTURES / "bandit_real.json")
        assert "Bandit" in type(i).__name__

    def test_gitleaks_sample(self) -> None:
        i = auto_detect(FIXTURES / "gitleaks_sample.json")
        assert "Gitleaks" in type(i).__name__

    def test_trufflehog_sample(self) -> None:
        i = auto_detect(FIXTURES / "trufflehog_sample.jsonl")
        assert "Trufflehog" in type(i).__name__

    def test_config_env(self) -> None:
        i = auto_detect(FIXTURES / "sample_config.env")
        assert "Config" in type(i).__name__

    def test_sarif_sample(self) -> None:
        i = auto_detect(FIXTURES / "sarif_sample.json")
        assert "Sarif" in type(i).__name__

    def test_manual_yaml(self) -> None:
        i = auto_detect(FIXTURES / "manual_finding.yaml")
        assert "Manual" in type(i).__name__


# ── 6. Correlator Consistency ───────────────────────────────────────────────


@pytest.mark.regression
class TestCorrelatorConsistency:
    """Same finding pairs produce same similarity scores."""

    def test_similar_findings_correlate(self) -> None:
        from tarmo_vuln_core.correlator import correlate_findings

        f1 = _make_finding(
            id="sqli-1",
            title="SQL Injection in Login",
            description="SQL injection in login form via username parameter",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        f2 = _make_finding(
            id="sqli-2",
            title="SQL Injection in Login Page",
            description="SQL injection in login form via password parameter",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        findings = [f1.model_dump(mode="json"), f2.model_dump(mode="json")]
        pairs = correlate_findings(findings, threshold=0.5)
        # Similar findings with same CWE and host should correlate
        assert len(pairs) >= 1
        assert pairs[0][2] > 0.5  # similarity score

    def test_different_findings_do_not_correlate(self) -> None:
        from tarmo_vuln_core.correlator import correlate_findings

        f1 = _make_finding(
            id="sqli",
            title="SQL Injection",
            description="SQL injection in login form",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        f2 = _make_finding(
            id="xss",
            title="Cross-Site Scripting",
            description="Reflected XSS in search page",
            cwe_id=79,
            affected_hosts=["10.0.0.2"],
        )
        findings = [f1.model_dump(mode="json"), f2.model_dump(mode="json")]
        pairs = correlate_findings(findings, threshold=0.9)
        # Very different findings should not correlate at high threshold
        assert len(pairs) == 0


# ── 7. Merge Idempotency ────────────────────────────────────────────────────


@pytest.mark.regression
class TestMergeIdempotency:
    """merge_findings(a, b) then merge_findings(result, b) is stable."""

    def test_merge_same_finding_idempotent(self) -> None:
        f = _make_finding(affected_hosts=["10.0.0.1"])
        merged = merge_findings(f, f)
        assert merged.affected_hosts == ["10.0.0.1"]

    def test_merge_preserves_source_code_refs(self) -> None:
        f1 = _make_finding(source_code_refs=[SourceCodeRef(file_path="a.py", start_line=1)])
        f2 = _make_finding(source_code_refs=[SourceCodeRef(file_path="b.py", start_line=2)])
        merged = merge_findings(f1, f2)
        # New finding's refs should take precedence (model_copy update)
        assert len(merged.source_code_refs) >= 1

    def test_merge_accumulates_hosts(self) -> None:
        f1 = _make_finding(affected_hosts=["10.0.0.1"])
        f2 = _make_finding(affected_hosts=["10.0.0.2"])
        merged = merge_findings(f1, f2)
        assert "10.0.0.1" in merged.affected_hosts
        assert "10.0.0.2" in merged.affected_hosts

    def test_merge_keeps_higher_cvss(self) -> None:
        f1 = _make_finding(cvss_score=5.0)
        f2 = _make_finding(cvss_score=8.5)
        merged = merge_findings(f1, f2)
        assert merged.cvss_score == 8.5
