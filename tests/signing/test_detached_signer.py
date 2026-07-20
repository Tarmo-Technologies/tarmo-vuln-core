"""Tests for ECDSA detached .sig signing and verification of non-PDF formats."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from tarmo_vuln_core.signing import ReportSigner, SigningConfig, VerificationResult
from tarmo_vuln_core.signing.keygen import ensure_keys_exist


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
    )
    return ReportSigner.from_config(cfg)


class TestDetachedSigCreation:
    def test_creates_sig_file_for_html(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.html"
        report.write_text("<html><body>test</body></html>")
        signer.sign(report)
        assert (tmp_path / "report.html.sig").exists()

    def test_creates_sig_file_for_markdown(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("# Test Report\n\nContent here.")
        signer.sign(report)
        assert (tmp_path / "report.md.sig").exists()

    def test_creates_sig_file_for_docx(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.docx"
        report.write_bytes(b"PK fake docx content")
        signer.sign(report)
        assert (tmp_path / "report.docx.sig").exists()

    def test_sig_json_has_required_fields(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("# Report")
        signer.sign(report)
        sig_data = json.loads((tmp_path / "report.md.sig").read_text())
        assert sig_data["version"] == 1
        assert sig_data["algorithm"] == "ECDSA-P256-SHA256"
        assert "signed_at" in sig_data
        assert "sha256" in sig_data
        assert "signature" in sig_data
        assert "cert_fingerprint" in sig_data

    def test_sha256_in_sig_matches_file(self, signer: ReportSigner, tmp_path: Path) -> None:
        content = b"# Test Report\n\nImportant findings."
        report = tmp_path / "report.md"
        report.write_bytes(content)
        signer.sign(report)
        sig_data = json.loads((tmp_path / "report.md.sig").read_text())
        expected = hashlib.sha256(content).hexdigest()
        assert sig_data["sha256"] == expected

    def test_cert_fingerprint_format(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.html"
        report.write_text("<html/>")
        signer.sign(report)
        sig_data = json.loads((tmp_path / "report.html.sig").read_text())
        assert sig_data["cert_fingerprint"].startswith("sha256:")
        # fingerprint hex is 64 chars after "sha256:"
        assert len(sig_data["cert_fingerprint"]) == len("sha256:") + 64

    def test_signature_is_valid_base64(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("content")
        signer.sign(report)
        sig_data = json.loads((tmp_path / "report.md.sig").read_text())
        # Should not raise
        decoded = base64.b64decode(sig_data["signature"])
        assert len(decoded) > 0

    def test_does_not_create_sig_for_csv(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "findings.csv"
        report.write_text("id,severity\n1,HIGH")
        signer.sign(report)
        assert not (tmp_path / "findings.csv.sig").exists()

    def test_does_not_create_sig_for_sarif(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "findings.sarif"
        report.write_text('{"version":"2.1.0"}')
        signer.sign(report)
        assert not (tmp_path / "findings.sarif.sig").exists()


class TestDetachedSigVerification:
    def test_verify_valid_sig_returns_true(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("# Valid report")
        signer.sign(report)
        result = signer.verify(report)
        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert result.path == report

    def test_verify_returns_cert_subject(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("content")
        signer.sign(report)
        result = signer.verify(report)
        assert result.cert_subject is not None
        assert "Tarmo Report Signer" in result.cert_subject

    def test_verify_tampered_file_returns_false(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("# Original content")
        signer.sign(report)
        # Tamper with the file
        report.write_text("# TAMPERED content")
        result = signer.verify(report)
        assert result.valid is False
        assert result.error is not None

    def test_verify_missing_sig_returns_false(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("# Report without sig")
        result = signer.verify(report)
        assert result.valid is False
        assert result.error is not None

    def test_verify_returns_signed_at_datetime(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.md"
        report.write_text("content")
        signer.sign(report)
        result = signer.verify(report)
        assert result.signed_at is not None

    def test_verify_returns_cert_fingerprint(self, signer: ReportSigner, tmp_path: Path) -> None:
        report = tmp_path / "report.html"
        report.write_text("<html/>")
        signer.sign(report)
        result = signer.verify(report)
        assert result.cert_fingerprint is not None
        assert result.cert_fingerprint.startswith("sha256:")
