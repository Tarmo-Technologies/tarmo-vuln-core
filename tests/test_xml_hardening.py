"""XML hardening: entity-expansion / XXE payloads must be refused, never expanded.

The bundled expat (>= 2.4) already aborts a *full* billion-laughs bomb via its
amplification limit, but it still happily expands smaller internal entities and
resolves nothing to stop a quadratic blow-up below its 8 MiB activation
threshold. These tests therefore assert on the *refusal* path (defusedxml's
``EntitiesForbidden``) via the "forbidden" wording in the IngestorError, which
the stdlib ParseError path never produces.
"""

from __future__ import annotations

import resource
import struct
import time
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from tarmo_vuln_core import auto_detect
from tarmo_vuln_core.ingestors._xml import parse_xml_bytes, parse_xml_file, xml_first_tag
from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.acunetix import AcunetixIngestor
from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor
from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.ingestors.parsers.fortify import (
    MAX_FVDL_BYTES,
    MAX_FVDL_COMPRESSION_RATIO,
    FortifyIngestor,
)
from tarmo_vuln_core.ingestors.parsers.metasploit import MetasploitIngestor
from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor
from tarmo_vuln_core.ingestors.parsers.nexpose import NexposeIngestor
from tarmo_vuln_core.ingestors.parsers.nikto import NiktoIngestor
from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor
from tarmo_vuln_core.ingestors.parsers.openvas import OpenvasIngestor
from tarmo_vuln_core.ingestors.parsers.qualys import QualysIngestor
from tarmo_vuln_core.ingestors.parsers.srm import SrmIngestor
from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor

FIXTURES = Path(__file__).parent / "fixtures"


def _billion_laughs(root_open: str, root_close: str, *, levels: int = 9) -> str:
    """Classic lol9 entity bomb wrapped around the given root element markup."""
    lines = ['<?xml version="1.0"?>', "<!DOCTYPE lolz [", '<!ENTITY lol0 "lol">']
    for i in range(1, levels + 1):
        lines.append(f'<!ENTITY lol{i} "' + f"&lol{i - 1};" * 10 + '">')
    lines.append("]>")
    lines.append(f"{root_open}&lol{levels};{root_close}")
    return "\n".join(lines) + "\n"


def _small_entity(root_open: str, root_close: str) -> str:
    """A single tiny internal entity — stdlib expands this silently."""
    return (
        '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY e "expanded">]>\n'
        f"{root_open}&e;{root_close}\n"
    )


def _xxe(root_open: str, root_close: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
        f"{root_open}&xxe;{root_close}\n"
    )


_CPPCHECK_OPEN = (
    '<results version="2"><cppcheck version="2.13"/><errors>'
    '<error id="nullPointer" severity="error" msg="x">'
)
_CPPCHECK_CLOSE = "</error></errors></results>"
_CHECKMARX_OPEN = '<CxXMLResults CheckmarxVersion="9.0"><Query name="SQL_Injection">'
_CHECKMARX_CLOSE = "</Query></CxXMLResults>"
_FVDL_NS = "xmlns://www.fortifysoftware.com/schema/fvdl"
_FORTIFY_OPEN = f'<FVDL xmlns="{_FVDL_NS}"><Description>'
_FORTIFY_CLOSE = "</Description></FVDL>"
_NESSUS_OPEN = "<NessusClientData_v2><Report><ReportHost name='h'>"
_NESSUS_CLOSE = "</ReportHost></Report></NessusClientData_v2>"


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


# ── ingest(): payloads are refused with IngestorError ─────────────────────────


@pytest.mark.unit
class TestIngestRejectsEntityPayloads:
    @pytest.mark.parametrize(
        ("ingestor", "name", "open_", "close"),
        [
            (CppcheckIngestor(), "cppcheck.xml", _CPPCHECK_OPEN, _CPPCHECK_CLOSE),
            (CheckmarxIngestor(), "cx.xml", _CHECKMARX_OPEN, _CHECKMARX_CLOSE),
            (FortifyIngestor(), "audit.fvdl", _FORTIFY_OPEN, _FORTIFY_CLOSE),
            (NessusIngestor(), "scan.nessus", _NESSUS_OPEN, _NESSUS_CLOSE),
        ],
        ids=["cppcheck", "checkmarx", "fortify", "nessus"],
    )
    def test_billion_laughs_refused(
        self, tmp_path: Path, ingestor: object, name: str, open_: str, close: str
    ) -> None:
        path = _write(tmp_path, name, _billion_laughs(open_, close))
        with pytest.raises(IngestorError, match="forbidden"):
            ingestor.ingest(path)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        ("ingestor", "name", "open_", "close"),
        [
            (CppcheckIngestor(), "cppcheck.xml", _CPPCHECK_OPEN, _CPPCHECK_CLOSE),
            (CheckmarxIngestor(), "cx.xml", _CHECKMARX_OPEN, _CHECKMARX_CLOSE),
            (FortifyIngestor(), "audit.fvdl", _FORTIFY_OPEN, _FORTIFY_CLOSE),
            (NessusIngestor(), "scan.nessus", _NESSUS_OPEN, _NESSUS_CLOSE),
            (SrmIngestor(), "srm.xml", "<report><findings>", "</findings></report>"),
            (NexposeIngestor(), "nx.xml", "<NexposeReport>", "</NexposeReport>"),
            (AcunetixIngestor(), "acx.xml", "<ScanGroup>", "</ScanGroup>"),
            (NmapIngestor(), "nmap.xml", "<nmaprun>", "</nmaprun>"),
            (BurpIngestor(), "burp.xml", "<issues>", "</issues>"),
            (ZapIngestor(), "zap.xml", "<OWASPZAPReport>", "</OWASPZAPReport>"),
            (OpenvasIngestor(), "ov.xml", "<report>", "</report>"),
            (QualysIngestor(), "q.xml", "<ASSET_DATA_REPORT>", "</ASSET_DATA_REPORT>"),
            (NiktoIngestor(), "nikto.xml", "<niktoscan>", "</niktoscan>"),
            (MetasploitIngestor(), "msf.xml", "<MetasploitV5>", "</MetasploitV5>"),
        ],
        ids=[
            "cppcheck",
            "checkmarx",
            "fortify",
            "nessus",
            "srm",
            "nexpose",
            "acunetix",
            "nmap",
            "burp",
            "zap",
            "openvas",
            "qualys",
            "nikto",
            "metasploit",
        ],
    )
    def test_small_internal_entity_refused(
        self, tmp_path: Path, ingestor: object, name: str, open_: str, close: str
    ) -> None:
        """Even a harmless-looking entity is refused — stdlib would expand it."""
        path = _write(tmp_path, name, _small_entity(open_, close))
        with pytest.raises(IngestorError, match="forbidden"):
            ingestor.ingest(path)  # type: ignore[attr-defined]

    def test_external_entity_refused_checkmarx(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "cx.xml", _xxe(_CHECKMARX_OPEN, _CHECKMARX_CLOSE))
        with pytest.raises(IngestorError, match="forbidden"):
            CheckmarxIngestor().ingest(path)

    def test_error_names_tool_and_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "cppcheck.xml", _billion_laughs(_CPPCHECK_OPEN, _CPPCHECK_CLOSE))
        with pytest.raises(IngestorError) as excinfo:
            CppcheckIngestor().ingest(path)
        msg = str(excinfo.value)
        assert "cppcheck" in msg
        assert "cppcheck.xml" in msg

    def test_fpr_with_entity_bomb_refused(self, tmp_path: Path) -> None:
        fpr = tmp_path / "bomb.fpr"
        with zipfile.ZipFile(fpr, "w") as zf:
            zf.writestr("audit.fvdl", _billion_laughs(_FORTIFY_OPEN, _FORTIFY_CLOSE))
        with pytest.raises(IngestorError, match="forbidden"):
            FortifyIngestor().ingest(fpr)


# ── can_handle(): payloads make probes return False, never crash ───────────────


@pytest.mark.unit
class TestProbesRejectEntityPayloads:
    @pytest.mark.parametrize(
        ("ingestor", "name", "open_", "close"),
        [
            (CppcheckIngestor(), "cppcheck.xml", _CPPCHECK_OPEN, _CPPCHECK_CLOSE),
            (CheckmarxIngestor(), "cx.xml", _CHECKMARX_OPEN, _CHECKMARX_CLOSE),
            (FortifyIngestor(), "audit.fvdl", _FORTIFY_OPEN, _FORTIFY_CLOSE),
            (NessusIngestor(), "scan.nessus", _NESSUS_OPEN, _NESSUS_CLOSE),
            (SrmIngestor(), "srm.xml", "<report><findings>", "</findings></report>"),
            (NexposeIngestor(), "nx.xml", "<NexposeReport>", "</NexposeReport>"),
            (AcunetixIngestor(), "acx.xml", "<ScanGroup>", "</ScanGroup>"),
            (NmapIngestor(), "nmap.xml", "<nmaprun>", "</nmaprun>"),
            (BurpIngestor(), "burp.xml", "<issues>", "</issues>"),
            (ZapIngestor(), "zap.xml", "<OWASPZAPReport>", "</OWASPZAPReport>"),
            (OpenvasIngestor(), "ov.xml", "<report>", "</report>"),
            (QualysIngestor(), "q.xml", "<ASSET_DATA_REPORT>", "</ASSET_DATA_REPORT>"),
            (NiktoIngestor(), "nikto.xml", "<niktoscan>", "</niktoscan>"),
            (MetasploitIngestor(), "msf.xml", "<MetasploitV5>", "</MetasploitV5>"),
        ],
        ids=[
            "cppcheck",
            "checkmarx",
            "fortify",
            "nessus",
            "srm",
            "nexpose",
            "acunetix",
            "nmap",
            "burp",
            "zap",
            "openvas",
            "qualys",
            "nikto",
            "metasploit",
        ],
    )
    def test_probe_returns_false_on_entity_payload(
        self, tmp_path: Path, ingestor: object, name: str, open_: str, close: str
    ) -> None:
        path = _write(tmp_path, name, _small_entity(open_, close))
        assert ingestor.can_handle(path) is False  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        ("ingestor", "raw"),
        [
            (CheckmarxIngestor(), _small_entity(_CHECKMARX_OPEN, _CHECKMARX_CLOSE)),
            (BurpIngestor(), _small_entity('<issues burpVersion="2023.1">', "</issues>")),
            (ZapIngestor(), _small_entity('<OWASPZAPReport version="2.14">', "</OWASPZAPReport>")),
        ],
        ids=["checkmarx", "burp", "zap"],
    )
    def test_extract_scanner_version_returns_none_on_entity_payload(
        self, ingestor: object, raw: str
    ) -> None:
        assert ingestor.extract_scanner_version(raw.encode()) is None  # type: ignore[attr-defined]

    def test_nessus_ingest_hosts_returns_empty_on_entity_payload(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "scan.nessus", _small_entity(_NESSUS_OPEN, _NESSUS_CLOSE))
        assert NessusIngestor().ingest_hosts(path) == []


# ── auto_detect(): a bomb named like a real report is rejected quickly ─────────


@pytest.mark.unit
class TestAutoDetectEntityBomb:
    def test_billion_laughs_named_cppcheck_rejected(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "cppcheck.xml", _billion_laughs(_CPPCHECK_OPEN, _CPPCHECK_CLOSE))
        rss_before_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        started = time.monotonic()
        with pytest.raises(IngestorError, match="No ingestor could handle 'cppcheck.xml'"):
            auto_detect(path)
        elapsed = time.monotonic() - started
        rss_after_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_growth_mib = (rss_after_kib - rss_before_kib) / 1024
        # lol9 fully expanded is ~3 GB; refusing it must be near-instant and cheap.
        assert elapsed < 5.0
        assert rss_growth_mib < 64

    def test_small_entity_named_nessus_rejected(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "scan.nessus", _small_entity(_NESSUS_OPEN, _NESSUS_CLOSE))
        with pytest.raises(IngestorError, match="No ingestor could handle 'scan.nessus'"):
            auto_detect(path)

    def test_legit_cppcheck_still_detected(self) -> None:
        assert isinstance(auto_detect(FIXTURES / "cppcheck_real.xml"), CppcheckIngestor)


# ── Fortify .fpr decompression cap ─────────────────────────────────────────────


def _fvdl_body(n_vulns: int = 1) -> str:
    vulns = "".join(
        f"<Vulnerability><ClassInfo><Type>SQL Injection {i}</Type>"
        "<DefaultSeverity>4.0</DefaultSeverity></ClassInfo></Vulnerability>"
        for i in range(n_vulns)
    )
    return f'<FVDL xmlns="{_FVDL_NS}"><Vulnerabilities>{vulns}</Vulnerabilities></FVDL>'


@pytest.mark.unit
class TestFortifyDecompressionCap:
    def test_default_cap_is_64_mib(self) -> None:
        assert MAX_FVDL_BYTES == 64 * 1024 * 1024

    def test_default_compression_ratio_limit_is_200(self) -> None:
        assert MAX_FVDL_COMPRESSION_RATIO == 200

    def test_fpr_under_cap_ingests(self, tmp_path: Path) -> None:
        fpr = tmp_path / "ok.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", _fvdl_body(2))
        findings = FortifyIngestor(max_fvdl_bytes=64 * 1024).ingest(fpr)
        assert len(findings) == 2
        assert findings[0].title == "SQL Injection 0"

    def test_fpr_over_cap_rejected_by_header(self, tmp_path: Path) -> None:
        body = _fvdl_body(50)
        fpr = tmp_path / "big.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", body)
        cap = len(body) - 1
        with pytest.raises(IngestorError, match=r"audit\.fvdl.*exceeds.*cap"):
            FortifyIngestor(max_fvdl_bytes=cap).ingest(fpr)

    def test_fpr_lying_header_rejected(self, tmp_path: Path) -> None:
        """A central directory that under-reports file_size cannot smuggle more bytes."""
        body = _fvdl_body(50).encode()
        fpr = tmp_path / "liar.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", body)
        raw = bytearray(fpr.read_bytes())
        real_size = len(body).to_bytes(4, "little")
        fake_size = (16).to_bytes(4, "little")
        # Patch the uncompressed-size field in both the local header and the
        # central directory entry.
        assert raw.count(real_size) >= 2
        raw = bytearray(bytes(raw).replace(real_size, fake_size))
        fpr.write_bytes(bytes(raw))
        with pytest.raises(IngestorError):
            FortifyIngestor(max_fvdl_bytes=1024).ingest(fpr)

    def test_bounded_reader_enforces_cap_independently_of_header(self) -> None:
        """The chunked reader itself stops at the cap, whatever the header claimed."""
        import io

        from tarmo_vuln_core.ingestors.parsers.fortify import _BoundedReader

        over = _BoundedReader(io.BytesIO(b"A" * 5000), max_bytes=4096, label="audit.fvdl")
        with pytest.raises(IngestorError, match=r"audit\.fvdl exceeds the decompressed size cap"):
            while over.read(1024):
                pass
        assert over.total == 4097  # stopped one byte past the cap, not at EOF
        exact = _BoundedReader(io.BytesIO(b"A" * 4096), max_bytes=4096, label="x")
        assert exact.read() == b"A" * 4096


# ── Fortify: compression-ratio guard and streaming parse (zip-bomb memory) ────

_FVDL_OPEN_ROOT = f'<FVDL xmlns="{_FVDL_NS}">'


def _element_bomb(n_bytes: int) -> bytes:
    """A well-formed FVDL whose body is *n_bytes* of dense empty elements."""
    return _FVDL_OPEN_ROOT.encode() + b"<a/>" * (n_bytes // 4) + b"</FVDL>"


def _patch_declared_size_field(fpr: Path, real: int, fake: int) -> None:
    """Rewrite a 32-bit size field in both the local and central headers."""
    raw = fpr.read_bytes()
    real_b, fake_b = struct.pack("<I", real), struct.pack("<I", fake)
    assert raw.count(real_b) >= 2
    fpr.write_bytes(raw.replace(real_b, fake_b))


#: Streaming parse peaks at ~0.85 MiB whatever the input size; the old
#: whole-tree parse needed ~43 MiB for a 2 MiB element bomb.
_BOMB_BYTES = 2 * 1024 * 1024
_PEAK_BOUND = 1536 * 1024


def _traced_peak(fn: object) -> tuple[object, int]:
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        result = fn()  # type: ignore[operator]
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


@pytest.mark.unit
class TestFortifyZipBombMemory:
    def test_high_ratio_fpr_rejected_up_front(self, tmp_path: Path) -> None:
        """16 MiB of <a/> deflates ~1000:1 -- refused from the header, before inflating."""
        body = _element_bomb(16 * 1024 * 1024)
        fpr = tmp_path / "bomb.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", body)
        assert fpr.stat().st_size < 64 * 1024
        started = time.monotonic()
        _none, peak = _traced_peak(lambda: _expect_ingest_error(fpr, _RATIO_MSG))
        assert time.monotonic() - started < 2.0
        assert peak < 1024 * 1024, f"peak {peak} bytes while refusing a ratio bomb"

    def test_lying_compress_size_cannot_dodge_ratio_guard(self, tmp_path: Path) -> None:
        """Over-reporting compress_size must not shrink the computed ratio: the
        denominator is clamped to the archive's real size."""
        body = _element_bomb(4 * 1024 * 1024)
        fpr = tmp_path / "liar.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", body)
        real_csize = zipfile.ZipFile(fpr).getinfo("audit.fvdl").compress_size
        _patch_declared_size_field(fpr, real_csize, 10 * 1024 * 1024)
        assert zipfile.ZipFile(fpr).getinfo("audit.fvdl").compress_size == 10 * 1024 * 1024
        _expect_ingest_error(fpr, _RATIO_MSG)

    def test_streaming_reader_enforces_ratio(self) -> None:
        """Defence in depth: the chunked reader re-checks the ratio on the bytes
        the decompressor actually produced, whatever the header declared."""
        import io

        from tarmo_vuln_core.ingestors.parsers.fortify import _BoundedReader

        reader = _BoundedReader(
            io.BytesIO(b"A" * (3 * 1024 * 1024)),
            max_bytes=64 * 1024 * 1024,
            label="audit.fvdl",
            compressed_size=4096,
            max_ratio=200,
        )
        with pytest.raises(IngestorError, match=_RATIO_MSG):
            while reader.read(16 * 1024):
                pass
        # Under the grace floor nothing trips, even at an absurd ratio.
        small = _BoundedReader(
            io.BytesIO(b"A" * (512 * 1024)),
            max_bytes=64 * 1024 * 1024,
            label="audit.fvdl",
            compressed_size=1,
            max_ratio=200,
        )
        total = 0
        while chunk := small.read(16 * 1024):
            total += len(chunk)
        assert total == 512 * 1024

    def test_small_high_ratio_entry_below_grace_floor_still_ingests(self, tmp_path: Path) -> None:
        """Tiny, very compressible reports are not false positives of the ratio guard."""
        vulns = (
            "<Vulnerability><ClassInfo><Type>SQL Injection</Type>"
            "<DefaultSeverity>4.0</DefaultSeverity></ClassInfo></Vulnerability>"
        ) * 5000
        body = f"{_FVDL_OPEN_ROOT}<Vulnerabilities>{vulns}</Vulnerabilities></FVDL>".encode()
        assert len(body) < 1024 * 1024
        fpr = tmp_path / "dense.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("audit.fvdl", body)
        info = zipfile.ZipFile(fpr).getinfo("audit.fvdl")
        assert info.file_size / info.compress_size > 200
        findings = FortifyIngestor().ingest(fpr)
        assert len(findings) == 5000
        assert findings[4999].title == "SQL Injection"

    def test_stored_element_bomb_parsed_in_bounded_memory(self, tmp_path: Path) -> None:
        """Ratio 1:1 (ZIP_STORED) passes the ratio guard; the streaming parser
        must still keep peak allocations far below the document size (the old
        whole-tree parse needed ~24 bytes of memory per input byte)."""
        body = _element_bomb(_BOMB_BYTES)
        fpr = tmp_path / "stored.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("audit.fvdl", body)
        findings, peak = _traced_peak(lambda: FortifyIngestor().ingest(fpr))
        assert findings == []
        assert peak < _PEAK_BOUND < len(body), f"peak {peak} bytes for a {len(body)}-byte FVDL"

    def test_standalone_fvdl_element_bomb_parsed_in_bounded_memory(self, tmp_path: Path) -> None:
        body = _element_bomb(_BOMB_BYTES)
        fvdl = tmp_path / "bomb.fvdl"
        fvdl.write_bytes(body)
        findings, peak = _traced_peak(lambda: FortifyIngestor().ingest(fvdl))
        assert findings == []
        assert peak < _PEAK_BOUND < len(body), f"peak {peak} bytes for a {len(body)}-byte FVDL"

    def test_bomb_nested_inside_vulnerability_bounded(self, tmp_path: Path) -> None:
        """Junk inside a retained Vulnerability subtree is discarded as it streams."""
        junk = b"<a/>" * (_BOMB_BYTES // 8)
        body = (
            _FVDL_OPEN_ROOT.encode()
            + b"<Vulnerabilities><Vulnerability><ClassInfo><Type>Path Manipulation</Type>"
            + b"<DefaultSeverity>5.0</DefaultSeverity>"
            + junk
            + b"</ClassInfo>"
            + junk
            + b"</Vulnerability></Vulnerabilities></FVDL>"
        )
        fvdl = tmp_path / "nested.fvdl"
        fvdl.write_bytes(body)
        findings, peak = _traced_peak(lambda: FortifyIngestor().ingest(fvdl))
        assert [f.title for f in findings] == ["Path Manipulation"]  # type: ignore[union-attr]
        assert peak < _PEAK_BOUND < len(body), f"peak {peak} bytes for a {len(body)}-byte FVDL"

    def test_wrong_root_rejected_before_reading_whole_document(self, tmp_path: Path) -> None:
        body = b"<NotFVDL>" + b"<a/>" * (4 * 1024 * 1024) + b"</NotFVDL>"
        fpr = tmp_path / "wrong.fpr"
        with zipfile.ZipFile(fpr, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("audit.fvdl", body)
        _none, peak = _traced_peak(
            lambda: _expect_ingest_error(fpr, "Unsupported Fortify XML root element")
        )
        assert peak < 1024 * 1024, f"peak {peak} bytes while refusing a non-FVDL root"


_RATIO_MSG = r"audit\.fvdl.*compression ratio.*exceeds.*200"


def _expect_ingest_error(path: Path, match: str) -> None:
    with pytest.raises(IngestorError, match=match):
        FortifyIngestor().ingest(path)


# ── Encoding declarations pyexpat cannot use must not escape as ValueError ────

_BAD_ENCODINGS = [
    pytest.param("shift_jis", id="multibyte-shift_jis"),
    pytest.param("euc-jp", id="multibyte-euc-jp"),
    pytest.param("big5", id="multibyte-big5"),
    pytest.param("x-bogus-enc", id="unknown-encoding"),
]


def _encoded_doc(encoding: str, root: str = "nmaprun") -> bytes:
    return f'<?xml version="1.0" encoding="{encoding}"?><{root}/>'.encode()


@pytest.mark.unit
class TestUnusableEncodingDeclarations:
    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_parse_xml_file_raises_ingestor_error(self, tmp_path: Path, encoding: str) -> None:
        path = tmp_path / "scan.xml"
        path.write_bytes(_encoded_doc(encoding))
        with pytest.raises(IngestorError, match=r"Failed to parse Nmap XML 'scan\.xml'"):
            parse_xml_file(path, fmt="Nmap")

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_parse_xml_bytes_raises_ingestor_error(self, encoding: str) -> None:
        with pytest.raises(IngestorError, match=r"Failed to parse Burp XML <bytes>"):
            parse_xml_bytes(_encoded_doc(encoding, "issues"), fmt="Burp")

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_xml_first_tag_raises_ingestor_error(self, tmp_path: Path, encoding: str) -> None:
        path = tmp_path / "scan.xml"
        path.write_bytes(_encoded_doc(encoding, "NexposeReport"))
        with pytest.raises(IngestorError, match=r"Failed to parse Nexpose XML 'scan\.xml'"):
            xml_first_tag(path, fmt="Nexpose")

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_auto_detect_raises_ingestor_error(self, tmp_path: Path, encoding: str) -> None:
        path = tmp_path / "scan.xml"
        path.write_bytes(_encoded_doc(encoding))
        with pytest.raises(IngestorError, match=r"No ingestor could handle 'scan\.xml'"):
            auto_detect(path)

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_auto_detect_fvdl_named_file(self, tmp_path: Path, encoding: str) -> None:
        path = tmp_path / "audit.fvdl"
        path.write_bytes(_encoded_doc(encoding, "FVDL"))
        with pytest.raises(IngestorError, match=r"No ingestor could handle 'audit\.fvdl'"):
            auto_detect(path)

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_scanner_version_returns_none(self, encoding: str) -> None:
        raw = _encoded_doc(encoding, 'CxXMLResults CheckmarxVersion="9.0"')
        assert CheckmarxIngestor().extract_scanner_version(raw) is None
        assert BurpIngestor().extract_scanner_version(_encoded_doc(encoding, "issues")) is None

    @pytest.mark.parametrize("encoding", _BAD_ENCODINGS)
    def test_fortify_ingest_fpr_raises_ingestor_error(self, tmp_path: Path, encoding: str) -> None:
        fpr = tmp_path / "enc.fpr"
        with zipfile.ZipFile(fpr, "w") as zf:
            zf.writestr("audit.fvdl", _encoded_doc(encoding, f'FVDL xmlns="{_FVDL_NS}"'))
        with pytest.raises(IngestorError, match=r"Failed to parse Fortify FVDL XML 'enc\.fpr'"):
            FortifyIngestor().ingest(fpr)
