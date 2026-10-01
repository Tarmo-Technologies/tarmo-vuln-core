"""Unit tests for the cppcheck XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestCppcheckIngestor:
    def setup_method(self) -> None:
        self.ingestor = CppcheckIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_cppcheck_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "cppcheck_real.xml") is True

    def test_cannot_handle_openvas_xml(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "openvas_sample.xml") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.xml") is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.xml")

    # -- Finding correctness tests -----------------------------------------------

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        # One finding per <error>: 13 errors minus 1 filtered noise (missingInclude) = 12
        assert len(findings) == 12

    def test_source_tool_is_cppcheck(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        assert all(f.source_tool == "cppcheck" for f in findings)

    def test_id_prefix_is_cppcheck(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        assert all(f.id.startswith("cppcheck-") for f in findings)

    def test_severity_deallocdealloc_is_high(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["deallocDealloc"].severity == Severity.HIGH

    def test_severity_unusedvariable_is_low(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["unusedVariable"].severity == Severity.LOW

    def test_unusedvariable_is_one_finding_per_error(self) -> None:
        """The same (id, msg) in two files is two findings, one host each (#7)."""
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        unused = [f for f in findings if f.raw_ref == "unusedVariable"]
        assert [f.affected_hosts for f in unused] == [
            ["src/lib/component1.cc"],
            ["src/lib/component2.cc"],
        ]
        # The id stays one per rule, as for SARIF; the location is not in it.
        assert [f.id for f in unused] == ["cppcheck-unusedvariable", "cppcheck-unusedvariable"]

    def test_missinginclude_filtered_as_noise(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # missingInclude is filtered as config noise
        assert "missingInclude" not in by_ref

    # -- source_code_refs tests ---------------------------------------------------

    def test_source_code_refs_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        unused = [f for f in findings if f.raw_ref == "unusedVariable"]
        # Each unusedVariable <error> has one location, so each finding has one ref.
        assert [[(r.file_path, r.start_line) for r in f.source_code_refs] for f in unused] == [
            [("src/lib/component1.cc", 17)],
            [("src/lib/component2.cc", 16)],
        ]

    def test_source_code_ref_file_path(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        dealloc = [f for f in findings if f.raw_ref == "deallocDealloc"]
        assert [f.source_code_refs[0].file_path for f in dealloc] == [
            "src/lib/component1.cc",
            "src/lib/component2.cc",
        ]

    def test_source_code_ref_has_line_number(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        dealloc = [f for f in findings if f.raw_ref == "deallocDealloc"]
        assert [f.source_code_refs[0].start_line for f in dealloc] == [47, 46]

    def test_double_free_is_vetted_where_its_sink_is(self) -> None:
        """#7: the merged doubleFree finding was vetted at component1.cc:47
        (``affected_hosts[0]``) while its last sink ref was component2.cc:46.

        After the split each finding's host is the file of its only (sink) ref.
        """
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        double_free = [f for f in findings if f.raw_ref == "doubleFree"]
        assert [
            (f.affected_hosts, [(r.file_path, r.start_line, r.is_sink) for r in f.source_code_refs])
            for f in double_free
        ] == [
            (["src/lib/component1.cc"], [("src/lib/component1.cc", 47, True)]),
            (["src/lib/component2.cc"], [("src/lib/component2.cc", 46, True)]),
        ]
        assert [f.description for f in double_free] == [
            "Memory pointed to by 'ip' is freed twice.",
            "Memory pointed to by 'ip' is freed twice.",
        ]

    def test_dot_slash_prefix_stripped_and_missing_file_kept(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        unused_fn = [f for f in findings if f.raw_ref == "unusedFunction"]
        assert [(f.affected_hosts, f.source_code_refs[0].start_line) for f in unused_fn] == [
            (["src/lib/component1.cc"], 24),
            (["src/lib/component_XXX.cc"], 24),
        ]

    def test_single_location_errors_have_no_cppcheck_locations(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        assert [f for f in findings if "cppcheck_locations" in f.extra_fields] == []

    def test_star_exclusion_no_source_code_refs(self) -> None:
        """Star wildcard locations should not produce source code refs."""
        # missingInclude is now filtered as noise, but verify star exclusion
        # still works for any future findings with star-only locations
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        # All remaining findings should have non-star file paths
        for f in findings:
            for ref in f.source_code_refs:
                assert ref.file_path != "*"

    # -- CData enrichment tests ---------------------------------------------------

    def test_cwe_populated_via_cdata(self) -> None:
        """CppCheck findings should have cwe_id populated from CData registry."""
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # unusedFunction → CWE-561 from CData
        assert by_ref["unusedFunction"].cwe_id == 561

    def test_cwe_none_for_unmapped_error_id(self) -> None:
        """Error IDs not in CData should have cwe_id=None."""
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # deallocDealloc is not in the CData mappings
        assert by_ref["deallocDealloc"].cwe_id is None

    def test_cdata_confidence_in_extra_fields(self) -> None:
        """Findings with CData confidence should store it in extra_fields."""
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # unusedFunction → CWE-561 with confidence "Inform"
        uf = by_ref["unusedFunction"]
        assert uf.cwe_id == 561
        assert uf.extra_fields.get("cdata_confidence") == "Inform"

    def test_config_noise_filtered_out(self) -> None:
        """Config noise errors like missingInclude should be filtered out."""
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        assert "missingInclude" not in by_ref

    def test_ctu_null_pointer_gets_specific_cwe(self, tmp_path: Path) -> None:
        report = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.13"/>
  <errors>
    <error id="ctunullpointer" severity="warning" msg="Null pointer dereference: arg">
      <location file="src/main.cc" line="12"/>
    </error>
  </errors>
</results>
"""
        path = tmp_path / "ctu.xml"
        path.write_text(report, encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 476

    def test_shift_too_many_bits_signed_gets_specific_cwe(self, tmp_path: Path) -> None:
        report = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.13"/>
  <errors>
    <error id="shiftTooManyBitsSigned" severity="error" msg="shift exceeds bit width">
      <location file="src/main.cc" line="12"/>
    </error>
  </errors>
</results>
"""
        path = tmp_path / "shift.xml"
        path.write_text(report, encoding="utf-8")

        findings = self.ingestor.ingest(path)

        assert findings[0].cwe_id == 758

    def test_cwe_attribute_used_when_cdata_has_none(self, tmp_path: Path) -> None:
        """cppcheck's own cwe= attribute backs up the CData registry."""
        report = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.17.1"/>
  <errors>
    <error id="bufferAccessOutOfBounds" severity="error" msg="Out of bounds: buf" cwe="788">
      <location file="csrc/parse.c" line="9"/>
    </error>
    <error id="deallocDealloc" severity="error" msg="Dealloc twice: ip" cwe="0">
      <location file="csrc/parse.c" line="20"/>
    </error>
    <error id="someNewCheck" severity="warning" msg="odd" cwe="not-a-number">
      <location file="csrc/parse.c" line="30"/>
    </error>
  </errors>
</results>
"""
        path = tmp_path / "cwe.xml"
        path.write_text(report, encoding="utf-8")

        by_ref = {f.raw_ref: f for f in self.ingestor.ingest(path)}

        assert by_ref["bufferAccessOutOfBounds"].cwe_id == 788
        assert by_ref["deallocDealloc"].cwe_id is None
        assert by_ref["someNewCheck"].cwe_id is None

    def test_cdata_cwe_wins_over_cwe_attribute(self, tmp_path: Path) -> None:
        report = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.17.1"/>
  <errors>
    <error id="ctunullpointer" severity="warning" msg="Null pointer dereference: arg" cwe="999">
      <location file="src/main.cc" line="12"/>
    </error>
  </errors>
</results>
"""
        path = tmp_path / "ctu.xml"
        path.write_text(report, encoding="utf-8")

        assert self.ingestor.ingest(path)[0].cwe_id == 476


VALUEFLOW = FIXTURES / "cppcheck_valueflow" / "cppcheck.xml"


@pytest.mark.unit
class TestCppcheckMultiLocation:
    """One finding per ``<error>``; only the primary ``<location>`` is a ref (#7).

    Which ``<location>`` is the primary one, and the evidence for it:

    * The cppcheck 2.13.0 manual (``man/manual.md``, "The ``<location>``
      element") says: "All locations related to an error are listed with
      ``<location>`` elements. The primary location is listed first."
    * ``ErrorMessage::toXML`` (``lib/errorlogger.cpp`` at tag 2.13.0) writes
      ``callStack`` with a reverse iterator, while the text template's
      ``{file}``/``{line}``/``{column}`` use ``callStack.back()``: the first
      XML ``<location>`` is the location the text output reports.
    * ``cppcheck_valueflow/cppcheck.xml`` is real ``cppcheck 2.13.0 --xml
      --enable=warning src/`` output (sources beside it). The text run of the
      same sources prints ``src/redundant.c:17:19: arrayIndexOutOfBoundsCond``
      and ``src/nullarg.c:3:6: ctunullpointer``: the first ``<location>`` of
      each error. ``--template-location`` lists the notes in call-stack order
      (condition or call site first, primary last), the reverse of the XML.
    * ``cppcheck_real.xml`` (cppcheck 1.61) has only single-location errors,
      and the old parser made every location a sink ref, so neither shows an
      order.
    """

    def setup_method(self) -> None:
        self.findings = CppcheckIngestor().ingest(VALUEFLOW)

    def _one(self, rule: str) -> Finding:
        [finding] = [f for f in self.findings if f.raw_ref == rule]
        return finding

    def test_one_finding_per_error_in_document_order(self) -> None:
        assert [f.raw_ref for f in self.findings] == [
            "nullPointer",
            "arrayIndexOutOfBoundsCond",
            "nullPointerRedundantCheck",
            "uninitvar",
            "ctunullpointer",
        ]
        assert [f.id for f in self.findings] == [
            "cppcheck-nullpointer",
            "cppcheck-arrayindexoutofboundscond",
            "cppcheck-nullpointerredundantcheck",
            "cppcheck-uninitvar",
            "cppcheck-ctunullpointer",
        ]

    def test_primary_location_is_the_only_ref(self) -> None:
        f = self._one("arrayIndexOutOfBoundsCond")
        assert f.source_code_refs == [
            SourceCodeRef(file_path="src/redundant.c", start_line=17, column=19)
        ]
        assert f.source_code_refs[0].is_sink is True
        assert f.affected_hosts == ["src/redundant.c"]
        assert f.cwe_id == 788

    def test_other_locations_kept_with_info_in_document_order(self) -> None:
        f = self._one("arrayIndexOutOfBoundsCond")
        assert f.extra_fields["cppcheck_locations"] == [
            {
                "file": "src/redundant.c",
                "line": 16,
                "column": 13,
                "info": "Assuming that condition 'idx<20' is not redundant",
            }
        ]

    def test_ctu_null_pointer_ref_is_the_dereference_not_the_call(self) -> None:
        f = self._one("ctunullpointer")
        assert [(r.file_path, r.start_line, r.column) for r in f.source_code_refs] == [
            ("src/nullarg.c", 3, 6)
        ]
        assert f.extra_fields["cppcheck_locations"] == [
            {
                "file": "src/nullarg.c",
                "line": 8,
                "column": 16,
                "info": "Calling function write_value, 1st argument is null",
            }
        ]
        assert f.cwe_id == 476

    def test_redundant_check_ref_is_the_dereference_not_the_condition(self) -> None:
        f = self._one("nullPointerRedundantCheck")
        assert [(r.file_path, r.start_line, r.column) for r in f.source_code_refs] == [
            ("src/redundant.c", 5, 14)
        ]
        assert [loc["line"] for loc in f.extra_fields["cppcheck_locations"]] == [6]

    def test_single_location_error_has_no_cppcheck_locations(self) -> None:
        f = self._one("uninitvar")
        assert [(r.file_path, r.start_line, r.column) for r in f.source_code_refs] == [
            ("src/redundant.c", 25, 12)
        ]
        assert "cppcheck_locations" not in f.extra_fields

    def test_no_ref_is_a_taint_source(self) -> None:
        assert [len(f.source_code_refs) for f in self.findings] == [1, 1, 1, 1, 1]
        assert [r.is_sink for f in self.findings for r in f.source_code_refs] == [True] * 5

    def test_cross_file_locations_do_not_become_refs_or_hosts(self, tmp_path: Path) -> None:
        report = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.13.0"/>
  <errors>
    <error id="ctunullpointer" severity="error" msg="Null pointer dereference: p" cwe="476">
      <location file="./src/use.c" line="3" column="6" info="Dereferencing argument p"/>
      <location file="*" line="0" column="0"/>
      <location file="./src/caller.c" line="8" column="0"/>
      <location file="src/main.c" line="2" column="5" info="Calling function f"/>
    </error>
  </errors>
</results>
"""
        path = tmp_path / "ctu.xml"
        path.write_text(report, encoding="utf-8")

        [f] = CppcheckIngestor().ingest(path)

        assert f.affected_hosts == ["src/use.c"]
        assert f.source_code_refs == [SourceCodeRef(file_path="src/use.c", start_line=3, column=6)]
        # "*" is skipped, "./" stripped, column 0 (cppcheck: unknown) and a missing info are None.
        assert f.extra_fields["cppcheck_locations"] == [
            {"file": "src/caller.c", "line": 8, "column": None, "info": None},
            {"file": "src/main.c", "line": 2, "column": 5, "info": "Calling function f"},
        ]
