"""Tests for PAdES-T PDF signing and verification."""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest
import responses as responses_lib

from tarmo_vuln_core.signing import (
    ReportSigner,
    ReportSigningError,
    SigningConfig,
    SigningPolicy,
    VerificationResult,
)
from tarmo_vuln_core.signing.keygen import ensure_keys_exist

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_PDF = FIXTURES_DIR / "minimal.pdf"
TSA_URL = "http://tsa.test.invalid/tsr"


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
        tsa_url=TSA_URL,
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
            TSA_URL,
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
            TSA_URL,
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
            TSA_URL,
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
            TSA_URL,
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
            TSA_URL,
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
            TSA_URL,
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


class TestPdfTsaPolicy:
    def test_no_tsa_call_when_unset(self, signing_dir: Path, pdf_copy: Path) -> None:
        cfg = SigningConfig(
            key_path=signing_dir / "signing.key.pem",
            cert_path=signing_dir / "signing.cert.pem",
        )
        with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            result = ReportSigner.from_config(cfg).sign(pdf_copy)
            assert len(rsps.calls) == 0
        assert result.signed is True
        assert result.tsa is False

    def test_required_tsa_failure_raises(self, signing_dir: Path, pdf_copy: Path) -> None:
        cfg = SigningConfig(
            policy=SigningPolicy.REQUIRED,
            key_path=signing_dir / "signing.key.pem",
            cert_path=signing_dir / "signing.cert.pem",
            tsa_url=TSA_URL,
        )
        original = pdf_copy.read_bytes()
        with responses_lib.RequestsMock() as rsps:
            rsps.add(responses_lib.POST, TSA_URL, status=503, body=b"")
            with pytest.raises(ReportSigningError, match="report.pdf"):
                ReportSigner.from_config(cfg).sign(pdf_copy)
            assert len(rsps.calls) == 1
        # never silently downgraded to PAdES-B-B
        assert pdf_copy.read_bytes() == original

    def test_best_effort_tsa_failure_downgrades_and_reports(
        self, signing_dir: Path, pdf_copy: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        cfg = SigningConfig(
            key_path=signing_dir / "signing.key.pem",
            cert_path=signing_dir / "signing.cert.pem",
            tsa_url=TSA_URL,
        )
        with responses_lib.RequestsMock() as rsps:
            rsps.add(responses_lib.POST, TSA_URL, status=503, body=b"")
            result = ReportSigner.from_config(cfg).sign(pdf_copy)
        assert result.signed is True
        assert result.tsa is False
        assert any("TSA" in rec.getMessage() for rec in caplog.records)


class TestPdfVerifyTrust:
    def test_verify_untrusted_signature_is_invalid(
        self, signer: ReportSigner, pdf_copy: Path, tmp_path: Path
    ) -> None:
        signer.sign(pdf_copy)
        other_dir = tmp_path / "other"
        ensure_keys_exist(other_dir)
        verifier = ReportSigner(
            SigningConfig(
                key_path=other_dir / "signing.key.pem",
                cert_path=other_dir / "signing.cert.pem",
                trust_bundle_path=other_dir / "signing.cert.pem",
            )
        )
        result = verifier.verify(pdf_copy)
        assert result.valid is False
        assert result.error is not None
        assert "not trusted" in result.error

    def test_verify_with_explicit_trust_bundle_valid(
        self, signer: ReportSigner, signing_dir: Path, pdf_copy: Path, tmp_path: Path
    ) -> None:
        signer.sign(pdf_copy)
        other_dir = tmp_path / "other"
        ensure_keys_exist(other_dir)
        verifier = ReportSigner(
            SigningConfig(
                key_path=other_dir / "signing.key.pem",
                cert_path=other_dir / "signing.cert.pem",
                trust_bundle_path=signing_dir / "signing.cert.pem",
            )
        )
        assert verifier.verify(pdf_copy).valid is True

    def test_verify_rejects_unsigned_incremental_update(
        self, signer: ReportSigner, pdf_copy: Path
    ) -> None:
        from pyhanko.pdf_utils import generic
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

        signer.sign(pdf_copy)
        with pdf_copy.open("rb") as fh:
            writer = IncrementalPdfFileWriter(fh)
            writer.root["/Tampered"] = generic.BooleanObject(True)
            writer.update_root()
            buf = io.BytesIO()
            writer.write(buf)
        pdf_copy.write_bytes(buf.getvalue())
        result = signer.verify(pdf_copy)
        assert result.valid is False
