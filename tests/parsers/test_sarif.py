"""Unit tests for the SARIF 2.1.0 ingestor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestSarifIngestor:
    def setup_method(self) -> None:
        self.ingestor = SarifIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_sarif_sample(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "sarif_sample.json") is True

    def test_cannot_handle_trivy_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "trivy_sample.json") is False

    def test_cannot_handle_nmap_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "nmap_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.json") is False

    def test_cannot_handle_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        assert self.ingestor.can_handle(bad) is False

    def test_cannot_handle_sarif_missing_runs(self, tmp_path: Path) -> None:
        f = tmp_path / "nosarif.json"
        f.write_text('{"version": "2.1.0"}')
        assert self.ingestor.can_handle(f) is False

    def test_cannot_handle_wrong_version(self, tmp_path: Path) -> None:
        f = tmp_path / "v1.json"
        f.write_text('{"version": "1.0.0", "runs": []}')
        assert self.ingestor.can_handle(f) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises_ingestor_error(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.json")

    def test_ingest_invalid_json_raises_ingestor_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        with pytest.raises(IngestorError, match="Failed to parse SARIF"):
            self.ingestor.ingest(bad)

    # -- Finding correctness tests -----------------------------------------------

    def test_ingest_returns_three_findings(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        assert len(findings) == 3

    def test_source_tool_is_sarif(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        assert all(f.source_tool == "sarif" for f in findings)

    def test_sql_injection_is_critical(self) -> None:
        # CWE-89 has security-severity: 9.0 → CRITICAL
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["CWE-89"].severity == Severity.CRITICAL

    def test_xss_is_medium(self) -> None:
        # CWE-79 has level=warning → MEDIUM
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["CWE-79"].severity == Severity.MEDIUM

    def test_info_note_is_low(self) -> None:
        # INFO-001 has level=note → LOW
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["INFO-001"].severity == Severity.LOW

    def test_title_from_rule_name(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["CWE-89"].title == "SQL Injection"
        assert by_rule["CWE-79"].title == "Cross-Site Scripting"

    def test_cwe_extracted_from_relationships(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["CWE-89"].cwe_id == 89
        assert by_rule["CWE-79"].cwe_id == 79

    def test_no_cwe_when_absent(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert by_rule["INFO-001"].cwe_id is None

    def test_host_extracted_from_logical_location(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert "10.0.0.1" in by_rule["CWE-89"].affected_hosts
        assert "10.0.0.2" in by_rule["CWE-79"].affected_hosts

    def test_description_from_result_message(self) -> None:
        # result.message.text takes priority over rule.fullDescription.text
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert "SQL injection found in login query" in by_rule["CWE-89"].description

    def test_remediation_from_help_text(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        assert "parameterized" in by_rule["CWE-89"].remediation

    def test_ids_are_prefixed_with_sarif(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        assert all(f.id.startswith("sarif-") for f in findings)

    # -- smoke test against real fixture -----------------------------------------
    # Source: microsoft/sarif-tutorials — ESLint simple example output
    # https://raw.githubusercontent.com/microsoft/sarif-tutorials/main/samples/1-Introduction/simple-example.sarif

    def test_ingest_real_sarif_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        # Microsoft tutorial has 1 result: no-unused-vars
        assert len(findings) == 1

    def test_ingest_real_sarif_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        assert all(f.source_tool == "sarif" for f in findings)

    def test_ingest_real_sarif_rule_id(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        assert findings[0].raw_ref == "no-unused-vars"

    def test_ingest_real_sarif_severity_from_level_error(self) -> None:
        # real fixture has level=error with no security-severity → HIGH
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        assert findings[0].severity == Severity.HIGH

    def test_ingest_real_sarif_message_in_description(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        # message.text is "'x' is assigned a value but never used."
        assert "assigned" in findings[0].description or "never used" in findings[0].description

    # -- source_code_refs tests ---------------------------------------------------

    def test_real_sarif_has_source_code_ref(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        assert len(findings[0].source_code_refs) == 1

    def test_real_sarif_source_code_ref_file_path(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        ref = findings[0].source_code_refs[0]
        assert "simple-example.js" in ref.file_path

    def test_real_sarif_source_code_ref_start_line(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        ref = findings[0].source_code_refs[0]
        assert ref.start_line == 1

    def test_sample_sarif_source_code_ref_from_physical_location(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "sarif_sample.json")
        by_rule = {f.raw_ref: f for f in findings}
        # CWE-89 has a physicalLocation with artifactLocation.uri
        sqli = by_rule["CWE-89"]
        assert len(sqli.source_code_refs) == 1
        assert "login" in sqli.source_code_refs[0].file_path

    def test_real_sarif_source_code_ref_column(self) -> None:
        """SARIF region.startColumn populates ref.column."""
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        ref = findings[0].source_code_refs[0]
        # sarif_real.json first result has region.startColumn == 5
        assert ref.column == 5

    def test_sarif_source_code_ref_symbol_from_logical_location(self) -> None:
        """logicalLocations[0].name (or .fullyQualifiedName) populates ref.symbol."""
        from tarmo_vuln_core.ingestors.parsers.sarif import _extract_source_code_refs

        synthetic_result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/auth/login.py"},
                        "region": {"startLine": 42, "startColumn": 17},
                    },
                    "logicalLocations": [
                        {"name": "execute_query", "kind": "function"},
                    ],
                }
            ]
        }
        refs = _extract_source_code_refs(synthetic_result)
        assert len(refs) == 1
        assert refs[0].symbol == "execute_query"
        assert refs[0].column == 17
        assert refs[0].start_line == 42

    def test_sarif_source_code_ref_symbol_prefers_fully_qualified_name(self) -> None:
        """fullyQualifiedName wins over plain name when both are present."""
        from tarmo_vuln_core.ingestors.parsers.sarif import _extract_source_code_refs

        synthetic_result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 10},
                    },
                    "logicalLocations": [
                        {
                            "name": "execute",
                            "fullyQualifiedName": "auth.login.execute",
                            "kind": "function",
                        },
                    ],
                }
            ]
        }
        refs = _extract_source_code_refs(synthetic_result)
        assert refs[0].symbol == "auth.login.execute"

    def test_sarif_source_code_ref_symbol_none_when_logical_locations_missing(self) -> None:
        """Most SARIF producers omit logicalLocations — symbol stays None."""
        from tarmo_vuln_core.ingestors.parsers.sarif import _extract_source_code_refs

        synthetic_result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 10, "startColumn": 5},
                    },
                }
            ]
        }
        refs = _extract_source_code_refs(synthetic_result)
        assert refs[0].symbol is None
        assert refs[0].column == 5

    def test_sarif_source_code_ref_is_sink_default_true(self) -> None:
        """SARIF findings are single-location sinks by default."""
        findings = self.ingestor.ingest(FIXTURES / "sarif_real.json")
        assert findings[0].source_code_refs[0].is_sink is True


def _write_sarif(tmp_path: Path, run: dict) -> Path:
    base_run: dict = {"tool": {"driver": {"name": "Example", "rules": [{"id": "R1"}]}}}
    base_run.update(run)
    p = tmp_path / "out.sarif"
    p.write_text(json.dumps({"version": "2.1.0", "runs": [base_run]}))
    return p


def _result_at(artifact_location: dict, line: int = 3) -> dict:
    return {
        "ruleId": "R1",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact_location,
                    "region": {"startLine": line},
                }
            }
        ],
    }


@pytest.mark.unit
class TestSarifPathProvenance:
    """uriBaseId / originalUriBaseIds resolution, file:/// URIs and artifact roles."""

    path = FIXTURES / "sarif_build_roots.sarif"

    def setup_method(self) -> None:
        self.findings = SarifIngestor().ingest(self.path)

    def test_one_finding_per_result(self) -> None:
        assert len(self.findings) == 7

    def test_codeql_external_cwe_tags_give_the_first_cwe(self) -> None:
        # CodeQL tags CWEs as external/cwe/cwe-NNN (zero-padded); the first tag wins.
        assert [(f.raw_ref, f.cwe_id) for f in self.findings[:2]] == [
            ("cpp/overflow-buffer", 119),
            ("cpp/uncontrolled-allocation-size", 190),
        ]
        assert {f.cwe_id for f in self.findings} == {119, 190}

    def test_chained_build_root_resolves_relative_to_source_root(self) -> None:
        # BUILDROOT = build/ under %SRCROOT% -> repo-relative build/gen/foo_idl.c
        f = self.findings[0]
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.start_line, ref.symbol) == (
            "build/gen/foo_idl.c",
            212,
            "foo_idl_unmarshal_request",
        )
        assert f.affected_hosts == []
        assert f.extra_fields["uri_base_id"] == "BUILDROOT"
        assert f.extra_fields["resolved_path"] == "/home/ci/work/build/gen/foo_idl.c"

    def test_artifact_roles_and_generated_marker_recorded(self) -> None:
        f = self.findings[0]
        assert f.extra_fields["artifact_roles"] == ["analysisTarget", "uncontrolled"]
        assert f.extra_fields["generated_hint"] is True

    def test_in_source_artifact_has_no_generated_hint(self) -> None:
        f = self.findings[1]
        assert f.source_code_refs[0].file_path == "src/foo_server.c"
        assert f.extra_fields["uri_base_id"] == "%SRCROOT%"
        assert f.extra_fields["resolved_path"] == "/home/ci/work/src/foo_server.c"
        assert f.extra_fields["artifact_roles"] == ["analysisTarget"]
        assert "generated_hint" not in f.extra_fields

    def test_absolute_file_uri_under_source_root_is_made_repo_relative(self) -> None:
        f = self.findings[2]
        assert f.source_code_refs[0].file_path == "src/util funcs/strbuf.c"
        assert f.extra_fields["resolved_path"] == "/home/ci/work/src/util funcs/strbuf.c"
        assert "uri_base_id" not in f.extra_fields

    def test_out_of_tree_base_resolves_to_absolute_path(self) -> None:
        f = self.findings[3]
        ref = f.source_code_refs[0]
        assert ref.file_path == "/tmp/ci-7f3e2a/obj/proto/msg.pb.cc"
        assert ref.symbol == "acme::proto::Msg::_InternalParse"
        assert f.extra_fields["uri_base_id"] == "OBJROOT"
        assert f.extra_fields["resolved_path"] == "/tmp/ci-7f3e2a/obj/proto/msg.pb.cc"

    def test_absolute_file_uri_outside_source_root_keeps_leading_slash(self) -> None:
        f = self.findings[4]
        assert f.source_code_refs[0].file_path == "/opt/vendor/include/zlib.h"

    def test_index_only_artifact_location_resolves_through_run_artifacts(self) -> None:
        f = self.findings[5]
        ref = f.source_code_refs[0]
        assert (ref.file_path, ref.start_line) == ("build/gen/foo_idl.c", 260)
        assert f.extra_fields["uri_base_id"] == "BUILDROOT"
        assert f.extra_fields["generated_hint"] is True

    def test_base_without_uri_keeps_relative_path_and_records_base(self) -> None:
        f = self.findings[6]
        assert f.source_code_refs[0].file_path == "bits/stdio2.h"
        assert f.extra_fields["uri_base_id"] == "SYSINCLUDE"
        assert "resolved_path" not in f.extra_fields

    def test_path_provenance_is_aligned_with_source_code_refs(self) -> None:
        f = self.findings[0]
        prov = f.extra_fields["path_provenance"]
        assert prov == [
            {
                "file_path": "build/gen/foo_idl.c",
                "uri": "gen/foo_idl.c",
                "uri_base_id": "BUILDROOT",
                "resolved_path": "/home/ci/work/build/gen/foo_idl.c",
                "artifact_roles": ["analysisTarget", "uncontrolled"],
                "generated_hint": True,
            }
        ]

    def test_file_uri_without_bases_keeps_leading_slash(self, tmp_path: Path) -> None:
        p = _write_sarif(tmp_path, {"results": [_result_at({"uri": "file:///home/ci/x.c"})]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "/home/ci/x.c"

    def test_windows_drive_file_uri_has_no_leading_slash(self) -> None:
        [f] = SarifIngestor().ingest(FIXTURES / "sarif_real.json")
        assert (
            f.source_code_refs[0].file_path
            == "C:/dev/sarif/sarif-tutorials/samples/Introduction/simple-example.js"
        )

    def test_srcroot_without_original_bases_stays_relative(self, tmp_path: Path) -> None:
        loc = {"uri": "app/views.py", "uriBaseId": "%SRCROOT%"}
        p = _write_sarif(tmp_path, {"results": [_result_at(loc)]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "app/views.py"
        assert f.extra_fields["uri_base_id"] == "%SRCROOT%"
        assert "resolved_path" not in f.extra_fields

    def test_cyclic_base_ids_do_not_loop(self, tmp_path: Path) -> None:
        bases = {"A": {"uri": "a/", "uriBaseId": "B"}, "B": {"uri": "b/", "uriBaseId": "A"}}
        loc = {"uri": "x.c", "uriBaseId": "A"}
        p = _write_sarif(tmp_path, {"originalUriBaseIds": bases, "results": [_result_at(loc)]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path.endswith("a/x.c")
        assert f.extra_fields["uri_base_id"] == "A"

    def test_unknown_base_id_keeps_the_repo_relative_uri(self, tmp_path: Path) -> None:
        """A base that is not a known build root (here ``SRC``) keeps ``src/x.c`` relative."""
        bases = {"SRC": {"uri": "file:///home/ci/repo/"}}
        loc = {"uri": "src/x.c", "uriBaseId": "SRC"}
        p = _write_sarif(tmp_path, {"originalUriBaseIds": bases, "results": [_result_at(loc)]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "src/x.c"
        assert f.extra_fields["uri_base_id"] == "SRC"
        assert f.extra_fields["resolved_path"] == "/home/ci/repo/src/x.c"

    def test_filesystem_root_base_keeps_the_relative_uri(self, tmp_path: Path) -> None:
        bases = {"ROOTPATH": {"uri": "file:///"}}
        loc = {"uri": "library/alpine", "uriBaseId": "ROOTPATH"}
        p = _write_sarif(tmp_path, {"originalUriBaseIds": bases, "results": [_result_at(loc)]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "library/alpine"
        assert f.extra_fields["resolved_path"] == "/library/alpine"

    @pytest.mark.parametrize("base_id", ["BUILDROOT", "%OUTDIR%", "build_dir", "OBJROOT"])
    def test_build_root_base_resolves_to_an_absolute_path(
        self, tmp_path: Path, base_id: str
    ) -> None:
        bases = {base_id: {"uri": "file:///tmp/ci-1/out/"}}
        loc = {"uri": "gen/foo_idl.c", "uriBaseId": base_id}
        p = _write_sarif(tmp_path, {"originalUriBaseIds": bases, "results": [_result_at(loc)]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "/tmp/ci-1/out/gen/foo_idl.c"

    def test_partial_fingerprints_recorded(self) -> None:
        f = self.findings[0]
        assert f.extra_fields["partial_fingerprints"] == {
            "primaryLocationLineHash": "5c0f3a9d1e2b7c44:1"
        }

    def test_plain_relative_uri_adds_no_provenance_fields(self, tmp_path: Path) -> None:
        p = _write_sarif(tmp_path, {"results": [_result_at({"uri": "src/app.py"})]})
        [f] = SarifIngestor().ingest(p)
        assert f.source_code_refs[0].file_path == "src/app.py"
        assert f.extra_fields == {}
