"""Smoke test: verify every public export, every parser, and every subsystem.

Catches broken imports, schema drift, and parser crashes before they reach
downstream consumers.

Runs on every push (~2s).
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ── 1. Public API Imports ─────────────────────────────────────────────────────


class TestPublicAPIImports:
    """Every symbol in __all__ is importable and is the correct type."""

    def test_all_exports_importable(self) -> None:
        import tarmo_vuln_core

        for name in tarmo_vuln_core.__all__:
            obj = getattr(tarmo_vuln_core, name)
            assert obj is not None, f"{name} exported as None"

    def test_finding_model_validates(self) -> None:
        from tarmo_vuln_core import Finding, Severity

        f = Finding(
            id="smoke-test",
            title="Smoke Test Finding",
            severity=Severity.HIGH,
            description="desc",
            impact="impact",
            remediation="fix it",
            source_tool="manual",
        )
        assert f.id == "smoke-test"
        assert f.severity == Severity.HIGH

    def test_finding_json_roundtrip(self) -> None:
        from tarmo_vuln_core import Finding, Severity

        f = Finding(
            id="roundtrip",
            title="RT",
            severity=Severity.MEDIUM,
            description="d",
            impact="i",
            remediation="r",
            source_tool="nmap",
            affected_hosts=["10.0.0.1"],
            cwe_id=89,
            cvss_score=7.5,
        )
        data = f.model_dump(mode="json")
        f2 = Finding(**data)
        assert f2.id == "roundtrip"
        assert f2.affected_hosts == ["10.0.0.1"]
        assert f2.cwe_id == 89
        assert f2.cvss_score == 7.5

    def test_host_model_validates(self) -> None:
        from tarmo_vuln_core import Host, HostProperty

        h = Host(address="10.0.0.1")
        assert h.address == "10.0.0.1"
        hp = HostProperty(key="os", value="Linux")
        assert hp.key == "os"

    def test_severity_ordering(self) -> None:
        from tarmo_vuln_core import Severity

        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_finding_status_values(self) -> None:
        from tarmo_vuln_core import FindingStatus

        assert FindingStatus.OPEN == "open"
        assert FindingStatus.RESOLVED == "resolved"
        assert FindingStatus.IN_PROGRESS == "in_progress"

    def test_evidence_model(self) -> None:
        from tarmo_vuln_core import Evidence, EvidenceType

        e = Evidence(filename="screenshot.png", evidence_type=EvidenceType.SCREENSHOT)
        assert e.filename == "screenshot.png"

    def test_instance_model(self) -> None:
        from tarmo_vuln_core import Instance

        inst = Instance(host="10.0.0.1", port=80, path="/login")
        assert inst.host == "10.0.0.1"
        assert inst.port == 80

    def test_dread_score(self) -> None:
        from tarmo_vuln_core import DreadScore

        d = DreadScore(
            damage=8,
            reproducibility=7,
            exploitability=6,
            affected_users=5,
            discoverability=4,
        )
        # total is the average (0-10 scale)
        assert d.total == 6.0

    def test_enums(self) -> None:
        from tarmo_vuln_core import PortState, Protocol, ServiceName

        assert PortState.OPEN == "open"
        assert Protocol.TCP == "tcp"
        assert ServiceName.HTTP == "http"

    def test_utilities(self) -> None:
        from tarmo_vuln_core import slugify

        assert slugify("SQL Injection in Login") == "sql-injection-in-login"


# ── 2. Every Parser Ingests Its Fixture ───────────────────────────────────────


class TestEveryParserSmoke:
    """Each parser can ingest at least one fixture without crashing."""

    def test_nmap_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor

        findings = NmapIngestor().ingest(FIXTURES / "nmap_sample.xml")
        assert len(findings) >= 1

    def test_nmap_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor

        findings = NmapIngestor().ingest(FIXTURES / "nmap_real.xml")
        assert len(findings) >= 1

    def test_nessus_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor

        findings = NessusIngestor().ingest(FIXTURES / "nessus_sample.nessus")
        assert len(findings) >= 1

    def test_nessus_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor

        findings = NessusIngestor().ingest(FIXTURES / "nessus_real.nessus")
        assert len(findings) == 12

    def test_burp_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor

        findings = BurpIngestor().ingest(FIXTURES / "burp_sample.xml")
        assert len(findings) >= 1

    def test_burp_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor

        findings = BurpIngestor().ingest(FIXTURES / "burp_real.xml")
        assert len(findings) == 7

    def test_metasploit_sample_csv(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.metasploit import MetasploitIngestor

        findings = MetasploitIngestor().ingest(FIXTURES / "metasploit_sample.csv")
        assert len(findings) >= 1

    def test_metasploit_real_xml(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.metasploit import MetasploitIngestor

        findings = MetasploitIngestor().ingest(FIXTURES / "metasploit_real.xml")
        assert len(findings) >= 1

    def test_zap_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor

        findings = ZapIngestor().ingest(FIXTURES / "zap_sample.xml")
        assert len(findings) >= 1

    def test_zap_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor

        findings = ZapIngestor().ingest(FIXTURES / "zap_real.xml")
        assert len(findings) >= 1

    def test_openvas_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.openvas import OpenvasIngestor

        findings = OpenvasIngestor().ingest(FIXTURES / "openvas_sample.xml")
        assert len(findings) >= 1

    def test_openvas_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.openvas import OpenvasIngestor

        findings = OpenvasIngestor().ingest(FIXTURES / "openvas_real.xml")
        assert len(findings) >= 1

    def test_qualys_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.qualys import QualysIngestor

        findings = QualysIngestor().ingest(FIXTURES / "qualys_real.xml")
        assert len(findings) >= 1

    def test_nexpose_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nexpose import NexposeIngestor

        findings = NexposeIngestor().ingest(FIXTURES / "nexpose_real.xml")
        assert len(findings) >= 1

    def test_nikto_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.nikto import NiktoIngestor

        findings = NiktoIngestor().ingest(FIXTURES / "nikto_real.xml")
        assert len(findings) >= 1

    def test_acunetix_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.acunetix import AcunetixIngestor

        findings = AcunetixIngestor().ingest(FIXTURES / "acunetix_real.xml")
        assert len(findings) >= 1

    def test_sslyze_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.sslyze import SslyzeIngestor

        findings = SslyzeIngestor().ingest(FIXTURES / "sslyze_real.json")
        assert len(findings) >= 1

    def test_tenable_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.tenable import TenableIngestor

        findings = TenableIngestor().ingest(FIXTURES / "tenable_sample.json")
        assert len(findings) >= 1

    def test_trivy_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.trivy import TrivyIngestor

        findings = TrivyIngestor().ingest(FIXTURES / "trivy_sample.json")
        assert len(findings) >= 1

    def test_trivy_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.trivy import TrivyIngestor

        findings = TrivyIngestor().ingest(FIXTURES / "trivy_real.json")
        assert len(findings) >= 1

    def test_wpscan_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.wpscan import WpscanIngestor

        findings = WpscanIngestor().ingest(FIXTURES / "wpscan_real.json")
        assert len(findings) >= 1

    def test_bloodhound_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.bloodhound import BloodHoundIngestor

        findings = BloodHoundIngestor().ingest(FIXTURES / "bloodhound_sample.json")
        assert len(findings) >= 1

    def test_hackerone_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.hackerone import HackerOneIngestor

        findings = HackerOneIngestor().ingest(FIXTURES / "hackerone_sample.json")
        assert len(findings) >= 1

    def test_manual_yaml(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.manual import ManualIngestor

        findings = ManualIngestor().ingest(FIXTURES / "manual_finding.yaml")
        assert len(findings) >= 1

    def test_manual_json(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.manual import ManualIngestor

        findings = ManualIngestor().ingest(FIXTURES / "manual_finding.json")
        assert len(findings) >= 1

    def test_manual_csv(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor

        findings = CsvFindingIngestor().ingest(FIXTURES / "manual_findings.csv")
        assert len(findings) >= 1

    def test_sarif_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor

        findings = SarifIngestor().ingest(FIXTURES / "sarif_sample.json")
        assert len(findings) == 3

    def test_sarif_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor

        findings = SarifIngestor().ingest(FIXTURES / "sarif_real.json")
        assert len(findings) >= 1

    def test_semgrep_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.semgrep import SemgrepIngestor

        findings = SemgrepIngestor().ingest(FIXTURES / "semgrep_real.sarif")
        assert len(findings) >= 1

    def test_bandit_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.bandit import BanditIngestor

        findings = BanditIngestor().ingest(FIXTURES / "bandit_real.json")
        assert len(findings) == 35

    def test_cppcheck_real(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor

        findings = CppcheckIngestor().ingest(FIXTURES / "cppcheck_real.xml")
        assert len(findings) == 6

    def test_gitleaks_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.gitleaks import GitleaksIngestor

        findings = GitleaksIngestor().ingest(FIXTURES / "gitleaks_sample.json")
        assert len(findings) == 3

    def test_trufflehog_sample(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.trufflehog import TrufflehogIngestor

        findings = TrufflehogIngestor().ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert len(findings) == 3


# ── 3. Ingestor Registry & Auto-Detection ────────────────────────────────────


class TestIngestorRegistrySmoke:
    def test_registry_has_38_parsers(self) -> None:
        from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER

        assert len(DEFAULT_REGISTRY_ORDER) == 38

    def test_auto_detect_nmap(self) -> None:
        from tarmo_vuln_core import auto_detect

        i = auto_detect(FIXTURES / "nmap_sample.xml")
        assert "Nmap" in type(i).__name__

    def test_auto_detect_nessus(self) -> None:
        from tarmo_vuln_core import auto_detect

        i = auto_detect(FIXTURES / "nessus_real.nessus")
        assert "Nessus" in type(i).__name__

    def test_auto_detect_manual_yaml(self) -> None:
        from tarmo_vuln_core import auto_detect

        i = auto_detect(FIXTURES / "manual_finding.yaml")
        assert "Manual" in type(i).__name__

    def test_get_by_format(self) -> None:
        from tarmo_vuln_core import get_by_format

        i = get_by_format("nmap")
        assert "Nmap" in type(i).__name__


# ── 4. Dedup & Merge ─────────────────────────────────────────────────────────


class TestDedupMergeSmoke:
    def test_dedup_removes_duplicates(self) -> None:
        from tarmo_vuln_core import Finding, Severity
        from tarmo_vuln_core.dedup import deduplicate_findings

        f = Finding(
            id="dup",
            title="Dup",
            severity=Severity.LOW,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
        )
        data = [f.model_dump(mode="json")] * 3
        result = deduplicate_findings(data)
        assert len(result) == 1

    def test_merge_accumulates_hosts(self) -> None:
        from tarmo_vuln_core import Finding, Severity, merge_findings

        f1 = Finding(
            id="m",
            title="M",
            severity=Severity.HIGH,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
            affected_hosts=["10.0.0.1"],
        )
        f2 = Finding(
            id="m",
            title="M",
            severity=Severity.HIGH,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
            affected_hosts=["10.0.0.2"],
        )
        merged = merge_findings(f1, f2)
        assert "10.0.0.1" in merged.affected_hosts
        assert "10.0.0.2" in merged.affected_hosts


# ── 5. Diff Engine ────────────────────────────────────────────────────────────


class TestDiffSmoke:
    def test_diff_no_changes(self) -> None:
        from tarmo_vuln_core import Finding, Severity, diff_findings

        f = Finding(
            id="same",
            title="Same",
            severity=Severity.LOW,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
        )
        result = diff_findings([f], [f])
        assert len(result.new) == 0
        assert len(result.resolved) == 0
        assert len(result.changed) == 0

    def test_diff_detects_new(self) -> None:
        from tarmo_vuln_core import Finding, Severity, diff_findings

        f = Finding(
            id="new",
            title="New",
            severity=Severity.HIGH,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
        )
        result = diff_findings([], [f])
        assert len(result.new) == 1
        assert result.new[0].id == "new"


# ── 6. Workflow State Machine ─────────────────────────────────────────────────


class TestWorkflowSmoke:
    def test_default_transitions_exist(self) -> None:
        from tarmo_vuln_core import DEFAULT_TRANSITIONS

        assert len(DEFAULT_TRANSITIONS) > 0

    def test_status_workflow_allows_open_to_in_progress(self) -> None:
        from tarmo_vuln_core import FindingStatus, StatusWorkflow

        wf = StatusWorkflow()
        assert wf.can_transition(FindingStatus.OPEN, FindingStatus.IN_PROGRESS)

    def test_status_workflow_rejects_invalid(self) -> None:
        from tarmo_vuln_core import FindingStatus, StatusWorkflow

        wf = StatusWorkflow()
        # open → verified is not a valid direct transition
        assert not wf.can_transition(FindingStatus.OPEN, FindingStatus.VERIFIED)


# ── 7. Library Loader & Matcher ───────────────────────────────────────────────


class TestLibrarySmoke:
    def test_library_loads(self) -> None:
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library

        lib = load_library(DEFAULT_LIBRARY_DIR)
        assert len(lib) > 50

    def test_matcher_enriches_by_id(self) -> None:
        from tarmo_vuln_core import Finding, Severity
        from tarmo_vuln_core.library.loader import DEFAULT_LIBRARY_DIR, load_library
        from tarmo_vuln_core.library.matcher import build_alias_index, match_finding

        lib = load_library(DEFAULT_LIBRARY_DIR)
        idx = build_alias_index(lib)
        f = Finding(
            id="sql-injection",
            title="SQLi",
            severity=Severity.HIGH,
            description="d",
            impact="i",
            remediation="r",
            source_tool="manual",
            cvss_score=None,
        )
        enriched = match_finding(f, lib, idx)
        assert enriched.cvss_score is not None


# ── 8. Correlator ─────────────────────────────────────────────────────────────


class TestCorrelatorSmoke:
    def test_correlate_similar_findings(self) -> None:
        from tarmo_vuln_core import Finding, Severity
        from tarmo_vuln_core.correlator import correlate_findings

        f1 = Finding(
            id="sqli-1",
            title="SQL Injection in Login",
            severity=Severity.HIGH,
            description="SQL injection via username",
            impact="i",
            remediation="r",
            source_tool="burp",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        f2 = Finding(
            id="sqli-2",
            title="SQL Injection in Login Page",
            severity=Severity.HIGH,
            description="SQL injection via password",
            impact="i",
            remediation="r",
            source_tool="zap",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        pairs = correlate_findings(
            [f1.model_dump(mode="json"), f2.model_dump(mode="json")],
            threshold=0.5,
        )
        assert len(pairs) >= 1


# ── 9. Rust Extension (optional) ─────────────────────────────────────────────


class TestRustExtensionSmoke:
    def test_rust_extension_importable(self) -> None:
        try:
            import vuln_core_rs

            assert callable(vuln_core_rs.deduplicate_findings)
            assert callable(vuln_core_rs.correlate_findings)
            assert callable(vuln_core_rs.version)
        except ImportError:
            pytest.skip("Rust extension not built")

    def test_rust_dedup(self) -> None:
        try:
            import vuln_core_rs
        except ImportError:
            pytest.skip("Rust extension not built")

        from tarmo_vuln_core import Finding, Severity

        f = Finding(
            id="rs-dup",
            title="Rust Dup",
            severity=Severity.LOW,
            description="d",
            impact="i",
            remediation="r",
            source_tool="t",
        )
        data = [f.model_dump(mode="json")] * 5
        result = vuln_core_rs.deduplicate_findings(data)
        assert len(result) == 1

    def test_rust_correlate(self) -> None:
        try:
            import vuln_core_rs
        except ImportError:
            pytest.skip("Rust extension not built")

        from tarmo_vuln_core import Finding, Severity

        f1 = Finding(
            id="rs-a",
            title="SQL Injection in Login",
            severity=Severity.HIGH,
            description="SQL injection via user param",
            impact="i",
            remediation="r",
            source_tool="burp",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        f2 = Finding(
            id="rs-b",
            title="SQL Injection in Login Form",
            severity=Severity.HIGH,
            description="SQL injection via pass param",
            impact="i",
            remediation="r",
            source_tool="zap",
            cwe_id=89,
            affected_hosts=["10.0.0.1"],
        )
        pairs = vuln_core_rs.correlate_findings(
            [f1.model_dump(mode="json"), f2.model_dump(mode="json")],
            0.5,
        )
        assert len(pairs) >= 1
