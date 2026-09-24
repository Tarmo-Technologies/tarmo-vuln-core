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
import time
import zipfile
from pathlib import Path

import pytest

from tarmo_vuln_core import auto_detect
from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.acunetix import AcunetixIngestor
from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor
from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.ingestors.parsers.fortify import MAX_FVDL_BYTES, FortifyIngestor
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
    def test_default_cap_is_512_mib(self) -> None:
        assert MAX_FVDL_BYTES == 512 * 1024 * 1024

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

        from tarmo_vuln_core.ingestors.parsers.fortify import _read_bounded

        with pytest.raises(IngestorError, match="exceeds"):
            _read_bounded(io.BytesIO(b"A" * 5000), max_bytes=4096, label="audit.fvdl")
        assert _read_bounded(io.BytesIO(b"A" * 4096), max_bytes=4096, label="x") == b"A" * 4096
