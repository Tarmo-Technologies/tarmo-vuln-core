"""Tests for tarmo_vuln_core.enrichment — NVD and LLM enrichment."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from tarmo_vuln_core.models import Finding, Severity


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


# ── NVD enrichment ───────────────────────────────────────────────────────────


class TestNvdEnrichment:
    def test_non_cve_ref_returns_original(self) -> None:
        from tarmo_vuln_core.enrichment.nvd import enrich_finding_from_nvd

        f = _make_finding(raw_ref="NESSUS-42873")
        result = enrich_finding_from_nvd(f)
        assert result is f

    def test_no_raw_ref_returns_original(self) -> None:
        from tarmo_vuln_core.enrichment.nvd import enrich_finding_from_nvd

        f = _make_finding(raw_ref=None)
        result = enrich_finding_from_nvd(f)
        assert result is f

    def test_enriches_from_cached_nvd_response(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.enrichment.nvd import enrich_finding_from_nvd

        cache_dir = tmp_path / "nvd_cache"
        cache_dir.mkdir()
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "NVD description"}],
                        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 6.1,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # noqa: E501
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }
        (cache_dir / "CVE-2021-12345.json").write_text(json.dumps(nvd_data))

        f = _make_finding(
            raw_ref="CVE-2021-12345",
            cvss_score=None,
            cvss_vector=None,
            cwe_id=None,
        )
        result = enrich_finding_from_nvd(f, cache_dir=cache_dir)
        assert result.cvss_score == 6.1
        assert result.cvss_version == "3.1"
        assert result.cwe_id == 79
        assert "CVSS:3.1" in result.cvss_vector

    def test_existing_fields_not_overwritten(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.enrichment.nvd import enrich_finding_from_nvd

        cache_dir = tmp_path / "nvd_cache"
        cache_dir.mkdir()
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/..."}}
                            ]
                        },
                    }
                }
            ]
        }
        (cache_dir / "CVE-2021-99999.json").write_text(json.dumps(nvd_data))

        f = _make_finding(raw_ref="CVE-2021-99999", cvss_score=5.0, cvss_vector="existing")
        result = enrich_finding_from_nvd(f, cache_dir=cache_dir)
        assert result.cvss_score == 5.0
        assert result.cvss_vector == "existing"

    def test_batch_enrichment_preserves_order(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.enrichment.nvd import enrich_findings_from_nvd

        findings = [
            _make_finding(id="f1", raw_ref=None),
            _make_finding(id="f2", raw_ref=None),
        ]
        result = enrich_findings_from_nvd(findings, cache_dir=tmp_path)
        assert len(result) == 2
        assert result[0].id == "f1"
        assert result[1].id == "f2"


# ── LLM enrichment ──────────────────────────────────────────────────────────


class TestLlmEnrichment:
    def test_build_finding_context(self) -> None:
        from tarmo_vuln_core.enrichment.llm import _build_finding_context

        f = _make_finding(
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N",
            cwe_id=79,
            raw_ref="CVE-2021-12345",
        )
        ctx = _build_finding_context(f)
        assert "Test Finding" in ctx
        assert "MEDIUM" in ctx
        assert "10.0.0.1" in ctx
        assert "CVE-2021-12345" in ctx

    def test_parse_steps(self) -> None:
        from tarmo_vuln_core.enrichment.llm import _parse_steps

        text = "1. First step\n2. Second step\n3. Third step"
        steps = _parse_steps(text)
        assert len(steps) == 3
        assert steps[0] == "First step"
        assert steps[2] == "Third step"

    def test_enrich_finding_skips_populated_fields(self) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig, enrich_finding_from_llm

        config = LLMConfig()
        f = _make_finding(description="Already populated", impact="Has impact")
        # Should not call the API since fields are populated and force=False
        with patch("tarmo_vuln_core.enrichment.llm._call_llm") as mock_llm:
            result = enrich_finding_from_llm(f, config, fields=["description", "impact"])
        mock_llm.assert_not_called()
        assert result is f

    def test_enrich_finding_calls_llm_for_empty_field(self) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig, enrich_finding_from_llm

        config = LLMConfig()
        f = _make_finding(description="")
        with patch("tarmo_vuln_core.enrichment.llm._call_llm", return_value="LLM generated desc"):
            result = enrich_finding_from_llm(f, config, fields=["description"])
        assert result.description == "LLM generated desc"

    def test_enrich_finding_force_regenerates(self) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig, enrich_finding_from_llm

        config = LLMConfig()
        f = _make_finding(description="Old description")
        with patch("tarmo_vuln_core.enrichment.llm._call_llm", return_value="Forced new desc"):
            result = enrich_finding_from_llm(f, config, fields=["description"], force=True)
        assert result.description == "Forced new desc"

    def test_batch_enrichment_filters_by_id(self) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig, enrich_findings_from_llm

        config = LLMConfig()
        findings = [
            _make_finding(id="f1", description=""),
            _make_finding(id="f2", description=""),
        ]
        with patch("tarmo_vuln_core.enrichment.llm._call_llm", return_value="Enriched"):
            result = enrich_findings_from_llm(findings, config, finding_id="f1")
        assert result[0].description == "Enriched"
        assert result[1].description == ""  # not enriched

    def test_llm_config_from_env(self, monkeypatch) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig

        monkeypatch.setenv("TARMO_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("TARMO_LLM_MODEL", "claude-3-opus")
        config = LLMConfig.from_env()
        assert config.provider == "anthropic"
        assert config.model == "claude-3-opus"

    def test_llm_config_from_env_fallback(self, monkeypatch) -> None:
        from tarmo_vuln_core.enrichment.llm import LLMConfig

        monkeypatch.delenv("TARMO_LLM_PROVIDER", raising=False)
        monkeypatch.setenv("PENTEST_SCRIBE_LLM_PROVIDER", "ollama")
        monkeypatch.setenv("PENTEST_SCRIBE_LLM_MODEL", "llama3")
        config = LLMConfig.from_env()
        assert config.provider == "ollama"
        assert config.model == "llama3"
