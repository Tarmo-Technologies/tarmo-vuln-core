"""Unit tests for the cppcheck XML ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.models import Severity

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
        # 7 original groups minus 1 filtered noise (missingInclude) = 6
        assert len(findings) == 6

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

    def test_grouping_unusedvariable_has_two_hosts(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        hosts = by_ref["unusedVariable"].affected_hosts
        assert len(hosts) == 2

    def test_missinginclude_filtered_as_noise(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # missingInclude is filtered as config noise
        assert "missingInclude" not in by_ref

    # -- source_code_refs tests ---------------------------------------------------

    def test_source_code_refs_populated(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        # unusedVariable has 2 locations across 2 files
        assert len(by_ref["unusedVariable"].source_code_refs) == 2

    def test_source_code_ref_file_path(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        ref = by_ref["deallocDealloc"].source_code_refs[0]
        assert "component1.cc" in ref.file_path

    def test_source_code_ref_has_line_number(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "cppcheck_real.xml")
        by_ref = {f.raw_ref: f for f in findings}
        ref = by_ref["deallocDealloc"].source_code_refs[0]
        assert ref.start_line == 47

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
