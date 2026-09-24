"""Unit tests for the Fortify FPR ingestor."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.fortify import FortifyIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestFortifyIngestor:
    def setup_method(self) -> None:
        self.ingestor = FortifyIngestor()

    def test_can_handle_fortify(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "fortify_sample.fpr") is True

    def test_cannot_handle_other(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "eslint_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.fpr") is False

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.fpr")

    def test_finding_count(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert len(findings) == 2

    def test_source_tool(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert all(f.source_tool == "fortify" for f in findings)

    def test_id_prefix(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        assert all(f.id.startswith("fortify-") for f in findings)

    def test_sql_injection_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.severity == Severity.HIGH

    def test_xss_severity(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        xss = [f for f in findings if "Cross-Site" in f.title][0]
        assert xss.severity == Severity.MEDIUM

    def test_sql_injection_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert sqli.cwe_id == 89

    def test_xss_cwe(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        xss = [f for f in findings if "Cross-Site" in f.title][0]
        assert xss.cwe_id == 79

    def test_source_code_refs(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_sample.fpr")
        sqli = [f for f in findings if "SQL" in f.title][0]
        assert len(sqli.source_code_refs) == 2
        assert sqli.source_code_refs[0].file_path == "src/db/query.java"
        assert sqli.source_code_refs[0].start_line == 45

    def test_can_handle_standalone_fvdl(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "fortify_realistic_sample.fvdl") is True

    def test_ingest_standalone_fvdl(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_realistic_sample.fvdl")
        assert len(findings) == 1
        assert findings[0].title == "Cross-Site Request Forgery"
        assert findings[0].source_code_refs[0].file_path == "public/category.html"
        assert findings[0].source_code_refs[0].start_line == 222

    def test_fvdl_without_rule_metadata_leaves_cwe_unset(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "fortify_realistic_sample.fvdl")
        assert findings[0].cwe_id is None


_NS = "xmlns://www.fortifysoftware.com/schema/fvdl"


def _fpr(tmp_path: Path, body: bytes, name: str = "x.fpr") -> Path:
    import zipfile

    fpr = tmp_path / name
    with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("audit.fvdl", body)
    return fpr


def _small_fvdl() -> bytes:
    return (
        f'<FVDL xmlns="{_NS}"><Vulnerabilities><Vulnerability><ClassInfo>'
        "<Type>SQL Injection</Type><DefaultSeverity>4.0</DefaultSeverity>"
        "</ClassInfo></Vulnerability></Vulnerabilities></FVDL>"
    ).encode()


def _central_header_offset(raw: bytes) -> int:
    return raw.index(b"PK\x01\x02")


@pytest.mark.unit
class TestFortifyFprArchiveErrors:
    """Archive-level failures must surface as IngestorError, never raw stdlib errors."""

    def test_encrypted_entry_rejected(self, tmp_path: Path) -> None:
        fpr = _fpr(tmp_path, _small_fvdl(), "enc.fpr")
        raw = bytearray(fpr.read_bytes())
        raw[6] |= 0x1  # local header general-purpose flag: encrypted
        raw[_central_header_offset(bytes(raw)) + 8] |= 0x1  # central directory flag
        fpr.write_bytes(bytes(raw))
        assert FortifyIngestor().can_handle(fpr) is True
        with pytest.raises(IngestorError, match=r"audit\.fvdl in 'enc\.fpr' is encrypted"):
            FortifyIngestor().ingest(fpr)

    @pytest.mark.parametrize("method", [9, 99], ids=["deflate64", "aes"])
    def test_unsupported_compression_method_rejected(self, tmp_path: Path, method: int) -> None:
        fpr = _fpr(tmp_path, _small_fvdl(), "method.fpr")
        raw = bytearray(fpr.read_bytes())
        raw[8:10] = method.to_bytes(2, "little")
        cd = _central_header_offset(bytes(raw))
        raw[cd + 10 : cd + 12] = method.to_bytes(2, "little")
        fpr.write_bytes(bytes(raw))
        with pytest.raises(IngestorError, match=r"Failed to read FPR 'method\.fpr'"):
            FortifyIngestor().ingest(fpr)

    def test_corrupt_deflate_stream_rejected(self, tmp_path: Path) -> None:
        fpr = _fpr(tmp_path, _small_fvdl(), "corrupt.fpr")
        raw = bytearray(fpr.read_bytes())
        data_start = 30 + len("audit.fvdl")
        raw[data_start : data_start + 4] = b"\xff\xff\xff\xff"  # BTYPE=11: invalid block
        fpr.write_bytes(bytes(raw))
        with pytest.raises(IngestorError, match=r"Failed to read FPR 'corrupt\.fpr'"):
            FortifyIngestor().ingest(fpr)

    def test_non_numeric_default_severity_rejected(self, tmp_path: Path) -> None:
        body = _small_fvdl().replace(b"4.0", b"high")
        fpr = _fpr(tmp_path, body, "sev.fpr")
        with pytest.raises(IngestorError, match=r"DefaultSeverity 'high'"):
            FortifyIngestor().ingest(fpr)


_RICH_FVDL = f"""<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="{_NS}" version="1.12">
  <Build><SourceFiles><File name="a"/></SourceFiles></Build>
  <Vulnerabilities>
    <Vulnerability>
      <ClassInfo>
        <Type>SQL Injection</Type><Type>Ignored Second Type</Type>
        <DefaultSeverity>5.0</DefaultSeverity>
      </ClassInfo>
      <ClassInfo><Type>Ignored Second ClassInfo</Type></ClassInfo>
      <AnalysisInfo><Unified><Context/><Trace>
        <Primary>
          <Entry><Node><SourceLocation path="src/Db.java" line="45"><x/></SourceLocation>
                       <SourceLocation path="ignored.java" line="1"/></Node>
                 <Node><SourceLocation path="ignored2.java" line="2"/></Node></Entry>
          <Entry><Node><SourceLocation path="src/Util.java" line="abc"/></Node></Entry>
          <Entry><Other/></Entry>
          <Entry><Node><SourceLocation path="" line="9"/></Node></Entry>
          <Entry><Node><SourceLocation path="src/Web.java" line="12"/></Node></Entry>
        </Primary>
        <Primary><Entry><Node><SourceLocation path="ignored3.java" line="3"/></Node></Entry>
        </Primary>
      </Trace></Unified></AnalysisInfo>
    </Vulnerability>
    <Vulnerability><AnalysisInfo/></Vulnerability>
    <Vulnerability><ClassInfo><Subtype>none</Subtype></ClassInfo></Vulnerability>
    <NotAVulnerability><ClassInfo><Type>Nope</Type></ClassInfo></NotAVulnerability>
    <Vulnerability><ClassInfo><Type>XSS</Type><DefaultSeverity>2.0</DefaultSeverity></ClassInfo></Vulnerability>
  </Vulnerabilities>
  <Vulnerabilities>
    <Vulnerability><ClassInfo><Type>From Second Block</Type></ClassInfo></Vulnerability>
  </Vulnerabilities>
  <Description>
    <Rule ruleID="sql injection"><MetaInfo>
      <Group name="Accuracy">1</Group><Group name="altcategoryCWE">CWE ID 89</Group>
    </MetaInfo><MetaInfo><Group name="altcategoryCWE">999</Group></MetaInfo></Rule>
    <Rule ruleID="cross site scripting"><MetaInfo>
      <Group name="altcategoryCWE">CWE-79</Group></MetaInfo></Rule>
  </Description>
  <Description><Rule ruleID="XSS"><MetaInfo>
    <Group name="altcategoryCWE">CWE-1</Group></MetaInfo></Rule></Description>
</FVDL>
"""


@pytest.mark.unit
class TestFortifyStreamingSemantics:
    """Pins the element-selection rules (first-match vs all-match) of the parser,
    including Description appearing after Vulnerabilities as in real FVDL."""

    @pytest.mark.parametrize("container", ["fpr", "fvdl"])
    def test_rich_document(self, tmp_path: Path, container: str) -> None:
        if container == "fpr":
            path = _fpr(tmp_path, _RICH_FVDL.encode(), "rich.fpr")
        else:
            path = tmp_path / "rich.fvdl"
            path.write_text(_RICH_FVDL)
        findings = FortifyIngestor().ingest(path)

        assert [f.title for f in findings] == ["SQL Injection", "Unknown", "XSS"]
        sqli, unknown, xss = findings

        assert sqli.severity == Severity.CRITICAL
        assert sqli.cwe_id == 89
        assert [(r.file_path, r.start_line) for r in sqli.source_code_refs] == [
            ("src/Db.java", 45),
            ("src/Util.java", None),
            ("src/Web.java", 12),
        ]
        assert sqli.affected_hosts == ["src/Db.java"]
        assert sqli.id == "fortify-sql-injection-db-java-l45"

        assert unknown.severity == Severity.MEDIUM
        assert unknown.cwe_id is None
        assert unknown.source_code_refs == []
        assert unknown.id == "fortify-unknown-unknown-lNone"

        assert xss.severity == Severity.LOW
        assert xss.cwe_id == 79
        assert xss.affected_hosts == []


@pytest.mark.unit
class TestFortifyNestingDepthGuard:
    """Deeply nested elements never close, so streaming + clear() cannot free
    them; the parser must cap nesting depth instead of letting the element
    stack grow with the input (~200 bytes of RAM per input byte)."""

    @staticmethod
    def _deep_fvdl(depth: int) -> bytes:
        # Incompressible trailing comment keeps the archive's ratio well under
        # the 200:1 zip-bomb limit, as a real attacker would.
        pad = b"<!--" + os.urandom(256 * 1024).hex().encode() + b"-->"
        return (
            f'<FVDL xmlns="{_NS}">'.encode() + b"<a>" * depth + b"</a>" * depth + b"</FVDL>" + pad
        )

    @pytest.mark.parametrize("container", ["fpr", "fvdl"])
    def test_deep_nesting_rejected(self, tmp_path: Path, container: str) -> None:
        import tracemalloc

        body = self._deep_fvdl(200_000)
        if container == "fpr":
            path = _fpr(tmp_path, body, "deep.fpr")
        else:
            path = tmp_path / "deep.fvdl"
            path.write_bytes(body)
        tracemalloc.start()
        try:
            with pytest.raises(
                IngestorError, match=r"nesting depth exceeds the limit of 256 in '?deep\.f"
            ):
                FortifyIngestor().ingest(path)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 16 * 1024 * 1024

    def test_depth_at_limit_accepted(self, tmp_path: Path) -> None:
        # FVDL root + 255 nested levels == 256 open elements: allowed.
        body = (
            f'<FVDL xmlns="{_NS}"><Vulnerabilities><Vulnerability><ClassInfo>'
            "<Type>SQL Injection</Type><DefaultSeverity>4.0</DefaultSeverity>"
            "</ClassInfo>"
        ).encode()
        body += b"<a>" * 253 + b"</a>" * 253 + b"</Vulnerability></Vulnerabilities></FVDL>"
        findings = FortifyIngestor().ingest(_fpr(tmp_path, body, "ok.fpr"))
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection"
