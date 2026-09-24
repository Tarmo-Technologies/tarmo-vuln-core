"""BHF (Build Harness Fuzz) fuzz + static ingestors, against real path-sanitized output.

Fixture layout (``tests/fixtures/bhf``):

* ``auto-run/`` — a ``bhf auto`` work directory: ``findings.csv`` (6 root-cause
  rows), ``findings/<id>/finding.json`` + ``testcase.bin`` and ``auto/run.json``
  (``source_root`` = ``/work/src``). The original work dir was ``/work/bhf`` and
  the BHF runtime lived at ``/opt/bhf``.
* ``static/`` — ``bhf static`` output as SARIF and native JSON (1 finding).
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

import pytest

from tarmo_vuln_core import FindingCategory, Severity, StackFrame, auto_detect, get_by_format
from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers import DEFAULT_REGISTRY_ORDER
from tarmo_vuln_core.ingestors.parsers.bhf import BhfIngestor, BhfStaticIngestor
from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor
from tarmo_vuln_core.ingestors.parsers.gnatsas import GnatSasIngestor
from tarmo_vuln_core.ingestors.parsers.manual import ManualIngestor
from tarmo_vuln_core.ingestors.parsers.pragmatic import PragmaticIngestor
from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.ingestors.parsers.sarp import SarpIngestor
from tarmo_vuln_core.ingestors.parsers.semgrep import SemgrepIngestor

FIXTURES = Path(__file__).parent.parent / "fixtures"
BHF = FIXTURES / "bhf"
WORK = BHF / "auto-run"
CSV_PATH = WORK / "findings.csv"
F0000 = "F-0000-c0dca483"

_CSV_ORDER = [
    "F-0000-c0dca483",
    "F-0002-1d8ca3de",
    "F-0001-bb0ed262",
    "F-0003-77f37013",
    "F-0004-8fb10837",
    "F-CAP-0000",
]


def _by_raw_ref(findings: list) -> dict:
    return {f.raw_ref: f for f in findings}


# ── BhfIngestor: detection ─────────────────────────────────────────────────────


@pytest.mark.unit
class TestBhfCanHandle:
    def setup_method(self) -> None:
        self.ing = BhfIngestor()

    def test_findings_csv(self) -> None:
        assert self.ing.can_handle(CSV_PATH) is True

    def test_work_directory(self) -> None:
        assert self.ing.can_handle(WORK) is True

    def test_single_finding_json(self) -> None:
        assert self.ing.can_handle(WORK / "findings" / F0000 / "finding.json") is True

    def test_capability_finding_json_without_signature(self) -> None:
        # F-CAP-0000 has cluster_key_full but no signature/cluster_key.
        assert self.ing.can_handle(WORK / "findings" / "F-CAP-0000" / "finding.json") is True

    def test_rejects_generic_csv(self) -> None:
        assert self.ing.can_handle(FIXTURES / "manual_findings.csv") is False
        assert self.ing.can_handle(FIXTURES / "flawfinder_real.csv") is False

    def test_rejects_csv_with_bhf_like_but_different_header(self, tmp_path: Path) -> None:
        p = tmp_path / "findings.csv"
        p.write_text("id,count,harness_id,rule_id,message\nX,1,H,R,m\n")
        assert self.ing.can_handle(p) is False

    def test_rejects_unrelated_json(self) -> None:
        assert self.ing.can_handle(FIXTURES / "manual_finding.json") is False
        assert self.ing.can_handle(FIXTURES / "trivy_real.json") is False

    def test_rejects_unrelated_directory(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("hi")
        assert self.ing.can_handle(tmp_path) is False

    def test_rejects_static_sarif(self) -> None:
        assert self.ing.can_handle(BHF / "static" / "static-report.sarif") is False

    def test_generic_csv_ingestors_do_not_shadow_bhf(self) -> None:
        assert isinstance(auto_detect(CSV_PATH), BhfIngestor)

    def test_auto_detect_work_directory(self) -> None:
        assert isinstance(auto_detect(WORK), BhfIngestor)

    def test_auto_detect_unrelated_directory_is_rejected_not_crashed(self, tmp_path: Path) -> None:
        # Every probe must tolerate a directory (XML probes used to raise
        # IsADirectoryError out of auto_detect).
        (tmp_path / "notes.txt").write_text("hi")
        with pytest.raises(IngestorError, match="No ingestor could handle"):
            auto_detect(tmp_path)

    def test_auto_detect_single_finding_json(self) -> None:
        detected = auto_detect(WORK / "findings" / F0000 / "finding.json")
        assert isinstance(detected, BhfIngestor)

    def test_generic_csv_still_goes_to_csv_ingestor(self) -> None:
        assert isinstance(auto_detect(FIXTURES / "manual_findings.csv"), CsvFindingIngestor)


# ── BhfIngestor: findings.csv ──────────────────────────────────────────────────


@pytest.mark.unit
class TestBhfIngestCsv:
    @pytest.fixture(scope="class")
    def findings(self) -> list:
        return BhfIngestor().ingest(CSV_PATH)

    def test_one_finding_per_csv_row(self, findings: list) -> None:
        with CSV_PATH.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 6
        assert len(findings) == 6
        assert [f.raw_ref for f in findings] == _CSV_ORDER

    def test_common_fields(self, findings: list) -> None:
        assert {f.source_tool for f in findings} == {"bhf"}
        assert {f.category for f in findings} == {FindingCategory.FUZZ}
        assert all(f.source_tools == ["bhf"] for f in findings)

    def test_f0000_core_mapping(self, findings: list) -> None:
        f = _by_raw_ref(findings)[F0000]
        assert f.title == "Heap-based Buffer Overflow in parse_record"
        assert f.severity == Severity.CRITICAL
        assert f.cwe_id == 122
        assert f.category == FindingCategory.FUZZ
        assert f.id == "bhf-F-0000-c0dca483"

    def test_f0000_title_has_no_asan_addresses(self, findings: list) -> None:
        f = _by_raw_ref(findings)[F0000]
        assert "0x" not in f.title
        assert "AddressSanitizer" not in f.title

    def test_f0000_sink_ref(self, findings: list) -> None:
        f = _by_raw_ref(findings)[F0000]
        # fix_location == sink here, so exactly one ref.
        assert len(f.source_code_refs) == 1
        ref = f.source_code_refs[0]
        assert ref.file_path == "parse.c"
        assert ref.start_line == 9
        assert ref.symbol == "parse_record"
        assert ref.is_sink is True

    def test_f0000_fuzz_evidence(self, findings: list) -> None:
        fz = _by_raw_ref(findings)[F0000].fuzz
        assert fz is not None
        assert fz.engine == "bhf"
        assert fz.finding_id == F0000
        assert fz.rule_id == "BHF-201"
        assert fz.exception_name == "ASAN_HEAP_BUFFER_OVERFLOW"
        assert fz.sanitizer == "asan"
        assert fz.classification == "unhandled"
        assert fz.verdict == "likely_reachable"
        assert fz.confidence == "medium"
        assert fz.confirmation == "fuzz"
        assert fz.harness_id == "H-C0005-3B81D475"
        assert fz.cluster_key == "cc6b46c403134e69"
        assert fz.signature == ("c0dca483634e97eccb8dc392359e31df7161004c60335111725d0d7033c4428b")
        assert fz.member_ids == []
        assert fz.cwe_ids == [122, 125]
        assert fz.prosthetics_used is False
        assert fz.reproducer_path == "findings/F-0000-c0dca483/testcase.bin"
        assert fz.replay_command == "bhf replay --finding findings/F-0000-c0dca483"

    def test_f0000_stack_is_project_frames_only(self, findings: list) -> None:
        fz = _by_raw_ref(findings)[F0000].fuzz
        assert fz is not None
        assert fz.stack == [StackFrame(file="parse.c", function="parse_record", line=9)]

    def test_no_absolute_or_runtime_paths_leak_into_stacks(self, findings: list) -> None:
        for f in findings:
            assert f.fuzz is not None
            for frame in f.fuzz.stack:
                assert frame.file is not None
                assert not frame.file.startswith("/")
                assert "harnesses" not in frame.file
                assert not frame.file.startswith("csu/")

    def test_f0000_description_and_remediation(self, findings: list) -> None:
        f = _by_raw_ref(findings)[F0000]
        assert f.description.startswith("This is a buffer overflow: while processing")
        assert "heap-buffer-overflow on address 0x502000000039" in f.description
        assert f.remediation.startswith(
            "Bounds-check the index/length before the access at `parse.c:9`"
        )
        assert "/work/src" not in f.remediation
        assert "/work/src" not in f.description

    def test_f0000_tags(self, findings: list) -> None:
        tags = _by_raw_ref(findings)[F0000].tags
        assert "bhf:verdict:likely_reachable" in tags
        assert "bhf:confidence:medium" in tags
        assert "bhf:classification:unhandled" in tags
        assert "bhf:non-defect" not in tags
        assert "bhf:prosthetics" not in tags

    def test_f0000_affected_hosts_is_relative_sink_file(self, findings: list) -> None:
        assert _by_raw_ref(findings)[F0000].affected_hosts == ["parse.c"]

    def test_f0001_second_harness(self, findings: list) -> None:
        f = _by_raw_ref(findings)["F-0001-bb0ed262"]
        assert f.title == "Heap-based Buffer Overflow in sum_table"
        assert f.cwe_id == 122
        assert f.fuzz is not None
        assert f.fuzz.cwe_ids == [122, 787]
        # BHF's exception.stack appends ASAN's "allocated by" frames after the crash
        # frames; the allocation site (parse.c:14) is a project frame and is kept.
        assert f.fuzz.stack == [
            StackFrame(file="parse.c", function="sum_table", line=17),
            StackFrame(file="parse.c", function="sum_table", line=14),
        ]

    def test_f0003_sink_falls_back_to_csv_columns(self, findings: list) -> None:
        # finding.json for F-0003 has no actionability.sink; the CSV row does.
        f = _by_raw_ref(findings)["F-0003-77f37013"]
        assert f.title == "OS command injection via controlled argv/cmdline in run_cmd"
        assert f.cwe_id == 78
        assert f.fuzz is not None
        assert f.fuzz.confirmation == "runtime"
        assert f.fuzz.classification == "oracle_hit"
        assert f.fuzz.sanitizer is None
        assert f.fuzz.stack == []
        assert [(r.file_path, r.start_line, r.symbol) for r in f.source_code_refs] == [
            ("cmd.c", 4, "run_cmd")
        ]
        assert "bhf:confidence:low" in f.tags

    def test_capability_finding(self, findings: list) -> None:
        f = _by_raw_ref(findings)["F-CAP-0000"]
        assert f.severity == Severity.MEDIUM
        assert f.cwe_id == 668
        assert f.title == "Input Triggered Capability in run_cmd"
        assert f.fuzz is not None
        assert f.fuzz.cwe_ids == [668]
        assert f.fuzz.classification == "capability"
        # No testcase.bin in this finding dir.
        assert f.fuzz.reproducer_path is None
        assert f.fuzz.replay_command == "bhf replay --finding findings/F-CAP-0000"
        assert f.fuzz.prosthetics_used is None
        assert "bhf:classification:capability" in f.tags
        assert [(r.file_path, r.start_line) for r in f.source_code_refs] == [("cmd.c", 4)]

    def test_severity_distribution(self, findings: list) -> None:
        sev = [f.severity for f in findings]
        assert sev.count(Severity.CRITICAL) == 5
        assert sev.count(Severity.MEDIUM) == 1


# ── BhfIngestor: alternate inputs ──────────────────────────────────────────────


@pytest.mark.unit
class TestBhfIngestAlternateInputs:
    def test_directory_matches_csv(self) -> None:
        via_dir = BhfIngestor().ingest(WORK)
        via_csv = BhfIngestor().ingest(CSV_PATH)
        assert len(via_dir) == 6
        assert [f.raw_ref for f in via_dir] == [f.raw_ref for f in via_csv]

    def test_get_by_format_bhf_ingests_directory(self) -> None:
        ing = get_by_format("bhf")
        assert isinstance(ing, BhfIngestor)
        findings = ing.ingest(WORK)
        assert len(findings) == 6
        assert _by_raw_ref(findings)[F0000].fuzz.reproducer_path == (  # type: ignore[union-attr]
            "findings/F-0000-c0dca483/testcase.bin"
        )

    def test_directory_without_csv_groups_finding_json(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK / "findings", work / "findings")
        shutil.copytree(WORK / "auto", work / "auto")
        findings = BhfIngestor().ingest(work)
        # Every fixture finding has a distinct cluster_key_full.
        assert len(findings) == 6
        f = _by_raw_ref(findings)[F0000]
        assert f.severity == Severity.CRITICAL
        assert f.cwe_id == 122
        assert f.source_code_refs[0].file_path == "parse.c"
        cap = _by_raw_ref(findings)["F-CAP-0000"]
        # Without the CSV, CWEs come from finding.json (CWE-77 for the capability).
        assert cap.cwe_id == 77
        assert cap.severity == Severity.MEDIUM

    def test_directory_without_csv_picks_highest_impact_representative(
        self, tmp_path: Path
    ) -> None:
        work = tmp_path / "work"
        src = json.loads((WORK / "findings" / F0000 / "finding.json").read_text())
        low = json.loads(json.dumps(src))
        low["id"] = "F-0007-deadbeef"
        low["actionability"]["impact"] = "low"
        for fid, doc in ((F0000, src), ("F-0007-deadbeef", low)):
            d = work / "findings" / fid
            d.mkdir(parents=True)
            (d / "finding.json").write_text(json.dumps(doc))
        findings = BhfIngestor(source_root=Path("/work/src")).ingest(work)
        assert len(findings) == 1
        assert findings[0].raw_ref == F0000
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].fuzz is not None
        assert findings[0].fuzz.member_ids == ["F-0007-deadbeef"]

    def test_single_finding_json(self) -> None:
        findings = BhfIngestor().ingest(WORK / "findings" / F0000 / "finding.json")
        assert len(findings) == 1
        f = findings[0]
        assert f.raw_ref == F0000
        assert f.cwe_id == 122
        assert f.source_code_refs[0].file_path == "parse.c"
        assert f.fuzz is not None
        assert f.fuzz.cwe_ids == [122, 125]
        assert f.fuzz.reproducer_path == "findings/F-0000-c0dca483/testcase.bin"

    def test_csv_without_finding_dirs_falls_back_to_columns(self, tmp_path: Path) -> None:
        csv_copy = tmp_path / "findings.csv"
        shutil.copy(CSV_PATH, csv_copy)
        findings = BhfIngestor(source_root=Path("/work/src")).ingest(csv_copy)
        assert len(findings) == 6
        f = _by_raw_ref(findings)[F0000]
        assert f.severity == Severity.CRITICAL
        assert f.cwe_id == 122
        assert f.fuzz is not None
        assert f.fuzz.cwe_ids == [122, 125]
        assert f.fuzz.exception_name == "ASAN_HEAP_BUFFER_OVERFLOW"
        assert f.fuzz.reproducer_path is None
        assert f.source_code_refs[0].file_path == "parse.c"
        assert f.source_code_refs[0].symbol == "parse_record"
        # No cwe_name without finding.json → humanized exception name.
        assert f.title == "Heap Buffer Overflow in parse_record"
        assert f.remediation.startswith("Check the requested index and offset")

    def test_source_root_override(self, tmp_path: Path) -> None:
        findings = BhfIngestor(source_root=Path("/work")).ingest(CSV_PATH)
        f = _by_raw_ref(findings)[F0000]
        assert f.source_code_refs[0].file_path == "src/parse.c"
        assert f.fuzz is not None
        assert f.fuzz.stack == [StackFrame(file="src/parse.c", function="parse_record", line=9)]

    def test_target_mount_prefix_is_stripped(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK / "findings", work / "findings")
        text = CSV_PATH.read_text().replace("/work/src/", "/target/lib/")
        (work / "findings.csv").write_text(text)
        findings = BhfIngestor().ingest(work)
        f = _by_raw_ref(findings)["F-CAP-0000"]
        assert [r.file_path for r in f.source_code_refs] == ["lib/cmd.c"]

    def test_info_impact_and_prosthetics_tags(self, tmp_path: Path) -> None:
        src = json.loads((WORK / "findings" / F0000 / "finding.json").read_text())
        src["actionability"]["impact"] = "info"
        src["actionability"]["prosthetics"] = {"used": True}
        p = tmp_path / "findings" / F0000 / "finding.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(src))
        [f] = BhfIngestor(source_root=Path("/work/src")).ingest(p)
        assert f.severity == Severity.INFO
        assert "bhf:non-defect" in f.tags
        assert "bhf:prosthetics" in f.tags
        assert f.fuzz is not None
        assert f.fuzz.prosthetics_used is True

    def test_intended_rejection_is_non_defect(self, tmp_path: Path) -> None:
        src = json.loads((WORK / "findings" / F0000 / "finding.json").read_text())
        src["classification"] = "intended_rejection"
        p = tmp_path / "finding.json"
        p.write_text(json.dumps(src))
        [f] = BhfIngestor(source_root=Path("/work/src")).ingest(p)
        assert "bhf:non-defect" in f.tags
        assert "bhf:classification:intended_rejection" in f.tags

    def test_unknown_impact_maps_to_medium(self, tmp_path: Path) -> None:
        src = json.loads((WORK / "findings" / F0000 / "finding.json").read_text())
        src["actionability"]["impact"] = "unknown"
        p = tmp_path / "finding.json"
        p.write_text(json.dumps(src))
        [f] = BhfIngestor(source_root=Path("/work/src")).ingest(p)
        assert f.severity == Severity.MEDIUM

    def test_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="not found"):
            BhfIngestor().ingest(tmp_path / "nope.csv")

    def test_non_bhf_csv_raises(self) -> None:
        with pytest.raises(IngestorError, match="BHF findings.csv"):
            BhfIngestor().ingest(FIXTURES / "manual_findings.csv")

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="BHF work directory"):
            BhfIngestor().ingest(tmp_path)

    def test_scanner_version_absent_in_run_json(self) -> None:
        raw = (WORK / "auto" / "run.json").read_bytes()
        assert BhfIngestor().extract_scanner_version(raw) is None

    def test_scanner_version_when_present(self) -> None:
        raw = json.dumps({"schema_version": 1, "bhf_version": "0.2.32"}).encode()
        assert BhfIngestor().extract_scanner_version(raw) == "0.2.32"


# ── BhfStaticIngestor ─────────────────────────────────────────────────────────

STATIC_SARIF = BHF / "static" / "static-report.sarif"
STATIC_JSON = BHF / "static" / "static-report.json"


@pytest.mark.unit
class TestBhfStaticIngestor:
    def test_can_handle_sarif_and_json(self) -> None:
        ing = BhfStaticIngestor()
        assert ing.can_handle(STATIC_SARIF) is True
        assert ing.can_handle(STATIC_JSON) is True

    def test_does_not_claim_other_sarif(self) -> None:
        ing = BhfStaticIngestor()
        assert ing.can_handle(FIXTURES / "semgrep_real.sarif") is False
        assert ing.can_handle(FIXTURES / "sarif_real.json") is False

    def test_auto_detect_prefers_bhf_over_generic_sarif(self) -> None:
        assert isinstance(auto_detect(STATIC_SARIF), BhfStaticIngestor)
        assert isinstance(auto_detect(STATIC_JSON), BhfStaticIngestor)

    def test_get_by_format(self) -> None:
        assert isinstance(get_by_format("bhf_static"), BhfStaticIngestor)
        assert isinstance(get_by_format("bhfstatic"), BhfStaticIngestor)

    @pytest.mark.parametrize("path", [STATIC_SARIF, STATIC_JSON], ids=["sarif", "json"])
    def test_single_finding_mapping(self, path: Path) -> None:
        findings = BhfStaticIngestor().ingest(path)
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe_id == 120
        assert f.category == FindingCategory.SAST
        assert f.source_tool == "bhf"
        assert f.source_tools == ["bhf"]
        # Generic SARIF maps level=error → HIGH (security-severity 7.0 → HIGH too);
        # the native JSON reports severity "high".
        assert f.severity == Severity.HIGH
        assert f.title == "Unbounded string copy (strcpy/strcat/gets) with no length limit"
        assert f.raw_ref == "BHF-401:cmd.c:9:unsafe-string-copy"
        assert f.id == "bhf-static-bhf-401-cmd-c-9-unsafe-string-copy"
        assert len(f.source_code_refs) == 1
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.start_line, ref.column) == ("cmd.c", 9, 46)
        assert ref.symbol == "copy_name"
        assert ref.is_sink is True
        assert set(f.tags) >= {
            "bhf:verdict:likely_reachable",
            "bhf:confidence:medium",
            "bhf:baseline:new",
            "bhf:triage:unreviewed",
        }
        assert f.remediation.startswith("Use a bounded copy")
        assert "strcpy/strcat/gets-style APIs without a visible bound" in f.description
        assert f.fuzz is None

    def test_scanner_version_from_sarif_driver(self) -> None:
        assert BhfStaticIngestor().extract_scanner_version(STATIC_SARIF.read_bytes()) == "0.2.32"

    def test_generic_sarif_unaffected(self) -> None:
        findings = SarifIngestor().ingest(STATIC_SARIF)
        assert len(findings) == 1
        assert findings[0].source_tool == "sarif"
        assert findings[0].title == "bhf.static/unsafe-string-copy"


# ── Registry ordering ─────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBhfRegistryOrder:
    def test_bhf_before_csv_catch_alls(self) -> None:
        idx = DEFAULT_REGISTRY_ORDER.index(BhfIngestor)
        for cls in (PragmaticIngestor, SarpIngestor, CsvFindingIngestor, ManualIngestor):
            assert idx < DEFAULT_REGISTRY_ORDER.index(cls), cls.__name__

    def test_bhf_static_before_sarif_family(self) -> None:
        idx = DEFAULT_REGISTRY_ORDER.index(BhfStaticIngestor)
        for cls in (SemgrepIngestor, GnatSasIngestor, SarifIngestor):
            assert idx < DEFAULT_REGISTRY_ORDER.index(cls), cls.__name__

    def test_exported(self) -> None:
        from tarmo_vuln_core.ingestors import parsers

        assert "BhfIngestor" in parsers.__all__
        assert "BhfStaticIngestor" in parsers.__all__
