"""Tests for the parser registry ordering."""

from __future__ import annotations


class TestParserRegistry:
    def test_all_new_ingestors_registered(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
        from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor
        from tarmo_vuln_core.ingestors.parsers.coverity import CoverityIngestor
        from tarmo_vuln_core.ingestors.parsers.eslint import EslintIngestor
        from tarmo_vuln_core.ingestors.parsers.fortify import FortifyIngestor
        from tarmo_vuln_core.ingestors.parsers.gnatsas import GnatSasIngestor
        from tarmo_vuln_core.ingestors.parsers.owasp_depcheck import OwaspDepcheckIngestor
        from tarmo_vuln_core.ingestors.parsers.pragmatic import PragmaticIngestor
        from tarmo_vuln_core.ingestors.parsers.pylint_ingestor import PylintIngestor
        from tarmo_vuln_core.ingestors.parsers.sarp import SarpIngestor
        from tarmo_vuln_core.ingestors.parsers.sigasi import SigasiIngestor
        from tarmo_vuln_core.ingestors.parsers.srm import SrmIngestor

        registry_classes = DEFAULT_REGISTRY_ORDER
        for cls in [
            CheckmarxIngestor,
            CoverityIngestor,
            EslintIngestor,
            FortifyIngestor,
            GnatSasIngestor,
            OwaspDepcheckIngestor,
            PragmaticIngestor,
            PylintIngestor,
            SarpIngestor,
            SigasiIngestor,
            SrmIngestor,
        ]:
            assert cls in registry_classes, f"{cls.__name__} not in registry"

    def test_gnatsas_before_sarif(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
        from tarmo_vuln_core.ingestors.parsers.gnatsas import GnatSasIngestor
        from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor

        gnat_idx = DEFAULT_REGISTRY_ORDER.index(GnatSasIngestor)
        sarif_idx = DEFAULT_REGISTRY_ORDER.index(SarifIngestor)
        assert gnat_idx < sarif_idx

    def test_sarp_before_csv(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
        from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor
        from tarmo_vuln_core.ingestors.parsers.sarp import SarpIngestor

        sarp_idx = DEFAULT_REGISTRY_ORDER.index(SarpIngestor)
        csv_idx = DEFAULT_REGISTRY_ORDER.index(CsvFindingIngestor)
        assert sarp_idx < csv_idx

    def test_pragmatic_before_csv(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
        from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor
        from tarmo_vuln_core.ingestors.parsers.pragmatic import PragmaticIngestor

        prag_idx = DEFAULT_REGISTRY_ORDER.index(PragmaticIngestor)
        csv_idx = DEFAULT_REGISTRY_ORDER.index(CsvFindingIngestor)
        assert prag_idx < csv_idx

    def test_register_all_creates_instances(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import register_all

        registry: list = []
        register_all(registry)
        # 27 original + 11 SAST + 2 BHF (fuzz + static) = 40
        assert len(registry) == 40

    def test_total_registry_count(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER

        assert len(DEFAULT_REGISTRY_ORDER) == 40
