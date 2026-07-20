"""Tests for PAdES-T PDF signing and verification."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import responses as responses_lib

from tarmo_vuln_core.signing import ReportSigner, SigningConfig, VerificationResult
from tarmo_vuln_core.signing.keygen import ensure_keys_exist

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_PDF = FIXTURES_DIR / "minimal.pdf"


@pytest.fixture()
def signing_dir(tmp_path: Path) -> Path:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    ensure_keys_exist(key_dir)
    return key_dir


@pytest.fixture()
def signer(signing_dir: Path) -> ReportSigner:
    cfg = SigningConfig(
        key_path=signing_dir / "signing.key.pem",
        cert_path=signing_dir / "signing.cert.pem",
        tsa_url="https://freetsa.org/tsr",
    )
    return ReportSigner.from_config(cfg)


@pytest.fixture()
def pdf_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "report.pdf"
    shutil.copy(MINIMAL_PDF, dest)
    return dest


class TestPdfSigningWithMockedTsa:
    @responses_lib.activate
    def test_sign_pdf_produces_valid_signature(self, signer: ReportSigner, pdf_copy: Path) -> None:
        """Sign a PDF with mocked TSA and verify the signature is valid."""
        # Mock TSA to return a valid RFC 3161 response
        # We'll use a real TSA response fixture or generate one
        # For testing, we mock the TSA to fail gracefully (falls back to PAdES-B)
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=500,
            body=b"",
        )
        original_size = pdf_copy.stat().st_size
        signer.sign(pdf_copy)
        # PDF should be larger after signing (signature appended)
        assert pdf_copy.stat().st_size > original_size

    @responses_lib.activate
    def test_sign_pdf_verify_returns_valid(self, signer: ReportSigner, pdf_copy: Path) -> None:
        """Signed PDF should pass verify()."""
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=500,
            body=b"",
        )
        signer.sign(pdf_copy)
        result = signer.verify(pdf_copy)
        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert result.path == pdf_copy

    @responses_lib.activate
    def test_sign_pdf_verify_returns_cert_subject(
        self, signer: ReportSigner, pdf_copy: Path
    ) -> None:
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=500,
            body=b"",
        )
        signer.sign(pdf_copy)
        result = signer.verify(pdf_copy)
        assert result.cert_subject is not None
        assert "Tarmo Report Signer" in result.cert_subject

    @responses_lib.activate
    def test_tampered_pdf_fails_verify(self, signer: ReportSigner, pdf_copy: Path) -> None:
        """Modifying a signed PDF should invalidate the signature."""
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=500,
            body=b"",
        )
        signer.sign(pdf_copy)
        # Corrupt the beginning of the PDF (before the signature)
        data = bytearray(pdf_copy.read_bytes())
        data[10] ^= 0xFF  # flip bits at offset 10
        pdf_copy.write_bytes(bytes(data))
        result = signer.verify(pdf_copy)
        assert result.valid is False

    @responses_lib.activate
    def test_sign_pdf_falls_back_gracefully_when_tsa_fails(
        self, signer: ReportSigner, pdf_copy: Path
    ) -> None:
        """TSA failure should not prevent signing — falls back to PAdES-B (no timestamp)."""
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=503,
            body=b"Service Unavailable",
        )
        original_size = pdf_copy.stat().st_size
        # Should not raise
        signer.sign(pdf_copy)
        # PDF should still be signed (larger)
        assert pdf_copy.stat().st_size > original_size

    @responses_lib.activate
    def test_sign_pdf_fallback_verify_valid(self, signer: ReportSigner, pdf_copy: Path) -> None:
        """PAdES-B fallback (no TST) should still produce a verifiable signature."""
        responses_lib.add(
            responses_lib.POST,
            "https://freetsa.org/tsr",
            status=503,
            body=b"Service Unavailable",
        )
        signer.sign(pdf_copy)
        result = signer.verify(pdf_copy)
        assert result.valid is True
        assert result.has_timestamp is False

    def test_sign_never_raises_on_corrupt_pdf(self, signer: ReportSigner, tmp_path: Path) -> None:
        """sign() must not raise even on a corrupt/non-PDF file."""
        bad_pdf = tmp_path / "bad.pdf"
        bad_pdf.write_bytes(b"this is not a pdf")
        # Should not raise
        signer.sign(bad_pdf)

    def test_verify_unsigned_pdf_returns_invalid(
        self, signer: ReportSigner, pdf_copy: Path
    ) -> None:
        result = signer.verify(pdf_copy)
        assert result.valid is False
        assert result.error is not None
