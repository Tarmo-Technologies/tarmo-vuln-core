"""FindingCategory enum, Finding.category, and per-ingestor category defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core import (
    BaseIngestor,
    Finding,
    FindingCategory,
    Severity,
    auto_detect,
    get_by_format,
)
from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.unit
class TestFindingCategoryEnum:
    def test_exact_values(self) -> None:
        assert [c.value for c in FindingCategory] == [
            "sast",
            "dast",
            "sca",
            "secrets",
            "fuzz",
            "infrastructure",
            "binary",
            "config",
            "manual",
            "other",
        ]

    def test_exported_from_models(self) -> None:
        from tarmo_vuln_core.models import FindingCategory as ModelsFindingCategory

        assert ModelsFindingCategory is FindingCategory
        assert ModelsFindingCategory("fuzz") is FindingCategory.FUZZ

    def test_in_top_level_all(self) -> None:
        import tarmo_vuln_core

        assert "FindingCategory" in tarmo_vuln_core.__all__


@pytest.mark.unit
class TestFindingCategoryField:
    def test_default_is_none(self) -> None:
        f = Finding(title="t", severity=Severity.LOW)
        assert f.category is None

    def test_coerces_string(self) -> None:
        f = Finding(title="t", severity=Severity.LOW, category="fuzz")
        assert f.category is FindingCategory.FUZZ

    def test_serializes_as_value(self) -> None:
        f = Finding(title="t", severity=Severity.LOW, category=FindingCategory.SCA)
        assert f.model_dump(mode="json")["category"] == "sca"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("SAST", FindingCategory.SAST),
            ("Dast", FindingCategory.DAST),
            ("  Fuzz  ", FindingCategory.FUZZ),
            (FindingCategory.CONFIG, FindingCategory.CONFIG),
        ],
    )
    def test_case_and_whitespace_insensitive(self, raw: object, expected: FindingCategory) -> None:
        f = Finding(title="t", severity=Severity.LOW, category=raw)
        assert f.category is expected
        assert f.extra_fields == {}

    def test_unknown_string_becomes_none_and_is_preserved(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Free-text categories (accepted-and-dropped before the enum existed)
        must not reject the finding; the raw value survives in extra_fields."""
        with caplog.at_level("WARNING", logger="tarmo_vuln_core.models.finding"):
            f = Finding(title="t", severity=Severity.LOW, category="Web Application")
        assert f.category is None
        assert f.extra_fields == {"category": "Web Application"}
        assert "Web Application" in caplog.text
        assert "category" in caplog.text

    def test_unknown_value_does_not_clobber_existing_extra_field(self) -> None:
        f = Finding.model_validate(
            {
                "title": "t",
                "severity": "LOW",
                "category": "quantum",
                "extra_fields": {"category": "kept", "team": "red"},
            }
        )
        assert f.category is None
        assert f.extra_fields == {"category": "kept", "team": "red"}

    @pytest.mark.parametrize("raw", [["web", "api"], 7, {"k": "v"}])
    def test_non_string_category_becomes_none(self, raw: object) -> None:
        f = Finding.model_validate({"title": "t", "severity": "LOW", "category": raw})
        assert f.category is None
        assert f.extra_fields == {"category": raw}

    def test_explicit_none_stays_none_without_extra_field(self) -> None:
        f = Finding(title="t", severity=Severity.LOW, category=None)
        assert f.category is None
        assert f.extra_fields == {}


_EXPECTED_CATEGORY: dict[str, FindingCategory] = {
    # SAST
    "SemgrepIngestor": FindingCategory.SAST,
    "BanditIngestor": FindingCategory.SAST,
    "EslintIngestor": FindingCategory.SAST,
    "CheckmarxIngestor": FindingCategory.SAST,
    "CoverityIngestor": FindingCategory.SAST,
    "CppcheckIngestor": FindingCategory.SAST,
    "FortifyIngestor": FindingCategory.SAST,
    "GnatSasIngestor": FindingCategory.SAST,
    "PylintIngestor": FindingCategory.SAST,
    "SarifIngestor": FindingCategory.SAST,
    "SigasiIngestor": FindingCategory.SAST,
    "SrmIngestor": FindingCategory.SAST,
    "PragmaticIngestor": FindingCategory.SAST,
    "SarpIngestor": FindingCategory.SAST,
    "BhfStaticIngestor": FindingCategory.SAST,
    # DAST
    "ZapIngestor": FindingCategory.DAST,
    "BurpIngestor": FindingCategory.DAST,
    "AcunetixIngestor": FindingCategory.DAST,
    "NiktoIngestor": FindingCategory.DAST,
    "WpscanIngestor": FindingCategory.DAST,
    # SCA
    "TrivyIngestor": FindingCategory.SCA,
    "OwaspDepcheckIngestor": FindingCategory.SCA,
    # Secrets
    "GitleaksIngestor": FindingCategory.SECRETS,
    "TrufflehogIngestor": FindingCategory.SECRETS,
    # Fuzz
    "BhfIngestor": FindingCategory.FUZZ,
    # Infrastructure
    "NessusIngestor": FindingCategory.INFRASTRUCTURE,
    "NexposeIngestor": FindingCategory.INFRASTRUCTURE,
    "NmapIngestor": FindingCategory.INFRASTRUCTURE,
    "OpenvasIngestor": FindingCategory.INFRASTRUCTURE,
    "QualysIngestor": FindingCategory.INFRASTRUCTURE,
    "TenableIngestor": FindingCategory.INFRASTRUCTURE,
    "SslyzeIngestor": FindingCategory.INFRASTRUCTURE,
    "MetasploitIngestor": FindingCategory.INFRASTRUCTURE,
    "BloodHoundIngestor": FindingCategory.INFRASTRUCTURE,
    # Binary / config / manual
    "StringsIngestor": FindingCategory.BINARY,
    "BinwalkIngestor": FindingCategory.BINARY,
    "ConfigAnalyzerIngestor": FindingCategory.CONFIG,
    "ManualIngestor": FindingCategory.MANUAL,
    "CsvFindingIngestor": FindingCategory.MANUAL,
    "HackerOneIngestor": FindingCategory.MANUAL,
}


@pytest.mark.unit
class TestIngestorCategoryAttribute:
    def test_base_default_is_none(self) -> None:
        assert BaseIngestor.category is None

    def test_every_registered_ingestor_has_expected_category(self) -> None:
        actual = {cls.__name__: cls.category for cls in DEFAULT_REGISTRY_ORDER}
        assert actual == _EXPECTED_CATEGORY


@pytest.mark.unit
class TestCategoryFilledOnIngest:
    def test_semgrep_via_get_by_format_is_sast(self) -> None:
        ingestor = get_by_format("semgrep")
        assert ingestor is not None
        findings = ingestor.ingest(FIXTURES / "semgrep_real.sarif")
        assert len(findings) == 6
        assert {f.category for f in findings} == {FindingCategory.SAST}
        assert findings[0].source_tool == "semgrep"

    def test_zap_via_auto_detect_is_dast(self) -> None:
        ingestor = auto_detect(FIXTURES / "zap_real.xml")
        findings = ingestor.ingest(FIXTURES / "zap_real.xml")
        assert len(findings) == 9
        assert {f.category for f in findings} == {FindingCategory.DAST}

    def test_trivy_via_auto_detect_is_sca(self) -> None:
        ingestor = auto_detect(FIXTURES / "trivy_real.json")
        findings = ingestor.ingest(FIXTURES / "trivy_real.json")
        assert len(findings) == 2
        assert {f.category for f in findings} == {FindingCategory.SCA}

    def test_explicit_category_is_not_overwritten(self, tmp_path: Path) -> None:
        class _Plugin(BaseIngestor):
            category = FindingCategory.CONFIG

            def can_handle(self, path: Path) -> bool:
                return True

            def ingest(self, path: Path) -> list[Finding]:
                return [
                    Finding(title="a", severity=Severity.LOW),
                    Finding(title="b", severity=Severity.LOW, category=FindingCategory.SECRETS),
                ]

        findings = _Plugin().ingest(tmp_path)
        assert [f.category for f in findings] == [
            FindingCategory.CONFIG,
            FindingCategory.SECRETS,
        ]

    def test_plugin_without_category_leaves_none(self, tmp_path: Path) -> None:
        class _Bare(BaseIngestor):
            def can_handle(self, path: Path) -> bool:
                return True

            def ingest(self, path: Path) -> list[Finding]:
                return [Finding(title="a", severity=Severity.LOW)]

        assert _Bare().ingest(tmp_path)[0].category is None
