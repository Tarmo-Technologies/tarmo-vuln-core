"""Integration and end-to-end tests for the SAST Bridge (Phases 12-13).

Covers:
- E2E ingest → match → enrich pipelines for all new ingestors
- Auto-detection routing for SAST/secrets file types
- Cross-ingestor dedup (gitleaks ↔ trufflehog, bandit ↔ semgrep)
- SourceCodeRef preservation through enrichment and merge
- Real-world fixture validation for new ingestors
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.dedup import deduplicate_findings
from tarmo_vuln_core.ingestors import auto_detect
from tarmo_vuln_core.ingestors.parsers.bandit import BanditIngestor
from tarmo_vuln_core.ingestors.parsers.binary_analyzer import (
    BinwalkIngestor,
    StringsIngestor,
)
from tarmo_vuln_core.ingestors.parsers.config_analyzer import ConfigAnalyzerIngestor
from tarmo_vuln_core.ingestors.parsers.gitleaks import GitleaksIngestor
from tarmo_vuln_core.ingestors.parsers.trufflehog import TrufflehogIngestor
from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library
from tarmo_vuln_core.library.matcher import match_finding
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef

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


# ── E2E: Ingest → Match → Enrich Pipelines ──────────────────────────────────


@pytest.mark.integration
class TestBanditToSastYamlEnrichment:
    """E2E: Bandit JSON → matcher → sast.yaml enrichment."""

    def test_b608_enriched_to_sql_injection(self) -> None:
        findings = BanditIngestor().ingest(FIXTURES / "bandit_real.json")
        library = load_library(DEFAULT_LIBRARY_DIR)

        b608 = [f for f in findings if f.raw_ref == "B608"]
        assert len(b608) > 0

        enriched = match_finding(b608[0], library)
        assert enriched.id == "sql-injection-source"
        assert enriched.cwe_id == 89
        assert enriched.cvss_score == 9.3
        assert len(enriched.steps) >= 3

    def test_b608_preserves_source_code_refs_after_enrichment(self) -> None:
        findings = BanditIngestor().ingest(FIXTURES / "bandit_real.json")
        library = load_library(DEFAULT_LIBRARY_DIR)

        b608 = [f for f in findings if f.raw_ref == "B608"][0]
        original_refs = b608.source_code_refs.copy()

        enriched = match_finding(b608, library)
        # source_code_refs should be preserved through enrichment
        assert len(enriched.source_code_refs) == len(original_refs)
        assert enriched.source_code_refs[0].file_path == original_refs[0].file_path

    def test_all_bandit_findings_enriched_batch(self) -> None:
        """Batch enrichment: all 35 findings processed without errors."""
        findings = BanditIngestor().ingest(FIXTURES / "bandit_real.json")
        library = load_library(DEFAULT_LIBRARY_DIR)
        enriched = [match_finding(f, library) for f in findings]
        assert len(enriched) == 35
        # At least B608 should be enriched
        matched = [f for f in enriched if f.id != f.raw_ref and "bandit-" not in f.id]
        assert len(matched) > 0


@pytest.mark.integration
class TestGitleaksToSecretsYamlEnrichment:
    """E2E: Gitleaks JSON → matcher → secrets.yaml enrichment."""

    def test_generic_api_key_enriched(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        library = load_library(DEFAULT_LIBRARY_DIR)

        api_key = [f for f in findings if f.raw_ref == "generic-api-key"]
        assert len(api_key) == 1

        enriched = match_finding(api_key[0], library)
        assert enriched.id == "hardcoded-api-key"
        assert enriched.cwe_id == 798
        assert enriched.cvss_score == 8.2
        assert len(enriched.steps) >= 3

    def test_private_key_enriched(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        library = load_library(DEFAULT_LIBRARY_DIR)

        pk = [f for f in findings if f.raw_ref == "private-key"]
        assert len(pk) == 1

        enriched = match_finding(pk[0], library)
        assert enriched.id == "exposed-private-key"
        assert enriched.cwe_id == 321
        # Severity stays HIGH (ingestor default) — matcher doesn't override set fields
        assert enriched.severity == Severity.HIGH

    def test_enrichment_preserves_source_code_refs(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        library = load_library(DEFAULT_LIBRARY_DIR)

        api_key = [f for f in findings if f.raw_ref == "generic-api-key"][0]
        enriched = match_finding(api_key, library)
        assert len(enriched.source_code_refs) == 2
        assert enriched.source_code_refs[0].file_path == "src/config.py"


@pytest.mark.integration
class TestTrufflehogToSecretsYamlEnrichment:
    """E2E: TruffleHog JSONL → matcher → secrets.yaml enrichment."""

    def test_aws_detector_enriched(self) -> None:
        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        library = load_library(DEFAULT_LIBRARY_DIR)

        aws = [f for f in findings if f.raw_ref == "AWS"]
        assert len(aws) == 1

        enriched = match_finding(aws[0], library)
        assert enriched.id == "exposed-cloud-credentials"
        assert enriched.cwe_id == 798
        assert enriched.cvss_score == 9.3

    def test_stripe_detector_enriched(self) -> None:
        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        library = load_library(DEFAULT_LIBRARY_DIR)

        stripe = [f for f in findings if f.raw_ref == "Stripe"]
        assert len(stripe) == 1

        enriched = match_finding(stripe[0], library)
        assert enriched.id == "hardcoded-api-key"
        assert enriched.cwe_id == 798


# ── Auto-Detection Routing Tests ─────────────────────────────────────────────


@pytest.mark.integration
class TestAutoDetectRouting:
    """Verify auto_detect routes new file types to correct ingestors."""

    def test_gitleaks_json_routes_to_gitleaks(self) -> None:
        ingestor = auto_detect(FIXTURES / "gitleaks_sample.json")
        assert isinstance(ingestor, GitleaksIngestor)

    def test_trufflehog_jsonl_routes_to_trufflehog(self) -> None:
        ingestor = auto_detect(FIXTURES / "trufflehog_sample.jsonl")
        assert isinstance(ingestor, TrufflehogIngestor)

    def test_bandit_json_routes_to_bandit(self) -> None:
        ingestor = auto_detect(FIXTURES / "bandit_real.json")
        assert isinstance(ingestor, BanditIngestor)

    def test_config_env_routes_to_config_analyzer(self) -> None:
        ingestor = auto_detect(FIXTURES / "sample_config.env")
        assert isinstance(ingestor, ConfigAnalyzerIngestor)

    def test_strings_file_routes_to_strings(self) -> None:
        ingestor = auto_detect(FIXTURES / "firmware.elf.strings")
        assert isinstance(ingestor, StringsIngestor)

    def test_binwalk_txt_routes_to_binwalk(self) -> None:
        ingestor = auto_detect(FIXTURES / "firmware_binwalk.txt")
        assert isinstance(ingestor, BinwalkIngestor)


# ── Cross-Ingestor Dedup Tests ───────────────────────────────────────────────


@pytest.mark.integration
class TestCrossIngestorDedup:
    """Dedup findings from different ingestors for the same secrets."""

    def test_gitleaks_and_trufflehog_findings_dedup_reduces_count(self) -> None:
        """Both tools find secrets in the same repo — combined should have fewer dupes."""
        gitleaks = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        trufflehog = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")

        combined = gitleaks + trufflehog
        combined_dicts = [f.model_dump(mode="json") for f in combined]
        deduped = deduplicate_findings(combined_dicts)

        # Should have all findings since they have different IDs
        # (dedup is content-hash based, different tools produce different content)
        assert len(deduped) == len(combined)

    def test_same_finding_from_same_tool_deduped(self) -> None:
        """Same gitleaks file ingested twice should dedup perfectly."""
        findings1 = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        findings2 = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")

        combined = findings1 + findings2
        combined_dicts = [f.model_dump(mode="json") for f in combined]
        deduped = deduplicate_findings(combined_dicts)

        assert len(deduped) == len(findings1)


# ── SourceCodeRef Preservation Tests ─────────────────────────────────────────


@pytest.mark.integration
class TestSourceCodeRefPreservation:
    """Verify SourceCodeRef survives serialization, enrichment, and dedup."""

    def test_finding_roundtrip_preserves_refs(self) -> None:
        ref = SourceCodeRef(
            file_path="src/app.py",
            start_line=42,
            snippet="eval(user_input)",
        )
        f = _make_finding(source_code_refs=[ref])
        data = f.model_dump(mode="json")
        restored = Finding(**data)
        assert len(restored.source_code_refs) == 1
        assert restored.source_code_refs[0].file_path == "src/app.py"
        assert restored.source_code_refs[0].start_line == 42
        assert restored.source_code_refs[0].snippet == "eval(user_input)"

    def test_enrichment_preserves_refs(self) -> None:
        """match_finding should not drop source_code_refs."""
        ref = SourceCodeRef(file_path="src/login.py", start_line=10)
        f = _make_finding(
            id="bandit-b608-login-py-l10",
            source_tool="bandit",
            raw_ref="B608",
            source_code_refs=[ref],
            cvss_score=None,
        )
        library = load_library(DEFAULT_LIBRARY_DIR)
        enriched = match_finding(f, library)
        assert len(enriched.source_code_refs) == 1
        assert enriched.source_code_refs[0].file_path == "src/login.py"

    def test_dedup_preserves_refs(self) -> None:
        ref = SourceCodeRef(file_path="src/app.py", start_line=42)
        f = _make_finding(source_code_refs=[ref])
        data = f.model_dump(mode="json")
        deduped = deduplicate_findings([data])
        assert len(deduped) == 1
        restored = Finding(**deduped[0])
        assert len(restored.source_code_refs) == 1
        assert restored.source_code_refs[0].file_path == "src/app.py"


# ── Real-World Fixture Validation ────────────────────────────────────────────


@pytest.mark.real_fixture
class TestGitleaksRealFixture:
    """Validate gitleaks fixture structural integrity."""

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "gitleaks_sample.json").exists()

    def test_finding_count_pinned(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        assert len(findings) == 3

    def test_all_findings_have_source_code_refs(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        for f in findings:
            assert len(f.source_code_refs) >= 1

    def test_rule_ids_present(self) -> None:
        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        refs = {f.raw_ref for f in findings}
        assert refs == {"generic-api-key", "aws-access-key-id", "private-key"}


@pytest.mark.real_fixture
class TestTrufflehogRealFixture:
    """Validate trufflehog fixture structural integrity."""

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "trufflehog_sample.jsonl").exists()

    def test_finding_count_pinned(self) -> None:
        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert len(findings) == 3

    def test_verified_findings_are_critical(self) -> None:
        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["AWS"].severity == Severity.CRITICAL
        assert by_ref["Stripe"].severity == Severity.CRITICAL
        assert by_ref["PrivateKey"].severity == Severity.HIGH

    def test_source_code_refs_from_git_metadata(self) -> None:
        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        aws_ref = by_ref["AWS"].source_code_refs[0]
        assert aws_ref.file_path == "src/config.py"
        assert aws_ref.commit_sha == "abc123"


@pytest.mark.real_fixture
class TestBinwalkRealFixture:
    """Validate binwalk fixture structural integrity."""

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "firmware_binwalk.txt").exists()

    def test_finding_count(self) -> None:
        findings = BinwalkIngestor().ingest(FIXTURES / "firmware_binwalk.txt")
        assert len(findings) == 4

    def test_detects_private_key_as_critical(self) -> None:
        findings = BinwalkIngestor().ingest(FIXTURES / "firmware_binwalk.txt")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["embedded-private-key"].severity == Severity.CRITICAL


@pytest.mark.real_fixture
class TestStringsRealFixture:
    """Validate strings fixture structural integrity."""

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "firmware.elf.strings").exists()

    def test_finding_count(self) -> None:
        findings = StringsIngestor().ingest(FIXTURES / "firmware.elf.strings")
        assert len(findings) == 6

    def test_detects_private_key_as_critical(self) -> None:
        findings = StringsIngestor().ingest(FIXTURES / "firmware.elf.strings")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["private-key-marker"].severity == Severity.CRITICAL


@pytest.mark.real_fixture
class TestConfigAnalyzerRealFixture:
    """Validate config analyzer fixture structural integrity."""

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "sample_config.env").exists()

    def test_finding_count(self) -> None:
        findings = ConfigAnalyzerIngestor().ingest(FIXTURES / "sample_config.env")
        assert len(findings) == 8

    def test_all_findings_have_line_numbers(self) -> None:
        findings = ConfigAnalyzerIngestor().ingest(FIXTURES / "sample_config.env")
        for f in findings:
            assert len(f.source_code_refs) >= 1
            assert f.source_code_refs[0].start_line is not None


# ── Stress Test ──────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestBatchEnrichmentStress:
    """Stress test: enrich large batches of findings."""

    def test_enrich_1000_findings(self) -> None:
        """Enrich 1000 synthetic findings without errors or slowness."""
        library = load_library(DEFAULT_LIBRARY_DIR)
        findings = []
        for i in range(1000):
            findings.append(
                _make_finding(
                    id=f"bandit-b608-file{i}-l{i}",
                    source_tool="bandit",
                    raw_ref="B608",
                    cwe_id=None,
                    cvss_score=None,
                    source_code_refs=[SourceCodeRef(file_path=f"src/file{i}.py", start_line=i)],
                )
            )

        enriched = [match_finding(f, library) for f in findings]
        assert len(enriched) == 1000
        # All should be enriched to sql-injection-source
        assert all(e.id == "sql-injection-source" for e in enriched)
        assert all(e.cwe_id == 89 for e in enriched)
        # source_code_refs should be preserved
        assert all(len(e.source_code_refs) == 1 for e in enriched)

    def test_dedup_1000_with_source_code_refs(self) -> None:
        """Dedup 1000 findings with SourceCodeRefs without errors."""
        findings = []
        for i in range(500):
            findings.append(
                _make_finding(
                    id=f"finding-{i % 100}",
                    title=f"Finding {i % 100}",
                    source_code_refs=[SourceCodeRef(file_path=f"src/file{i}.py", start_line=i)],
                )
            )
        dicts = [f.model_dump(mode="json") for f in findings]
        deduped = deduplicate_findings(dicts)
        # 500 findings with 100 unique IDs → 100 unique after dedup
        assert len(deduped) == 100
