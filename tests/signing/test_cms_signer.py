"""Tests for CMS (PKCS#7) detached signatures: ``<file>.p7s`` sidecars."""

from __future__ import annotations

import datetime
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tarmo_vuln_core._compat import UTC
from tarmo_vuln_core.signing import ReportSigner, SigningConfig, SigningPolicy
from tarmo_vuln_core.signing.cms_signer import CmsVerifyResult, sign_detached, verify_detached

_NOW = datetime.datetime.now(UTC)
_CRL_URL = "http://crl.test.invalid/ca.crl"


@dataclass
class Pki:
    ca_key: ec.EllipticCurvePrivateKey
    ca_cert: x509.Certificate
    ca_cert_path: Path
    leaf_key_path: Path
    leaf_cert_path: Path
    leaf_cert: x509.Certificate


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        ]
    )


def make_pki(base: Path, cn: str = "Test Signing CA", *, crl_dp: bool = False) -> Pki:
    """Build a CA and a document-signing leaf it issued, written as PEM under ``base``."""
    base.mkdir(parents=True, exist_ok=True)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("VAMS test signer"))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if crl_dp:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(_CRL_URL)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    leaf_cert = builder.sign(ca_key, hashes.SHA256())

    ca_cert_path = base / "ca.crt.pem"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    leaf_key_path = base / "signing.key.pem"
    leaf_key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    leaf_cert_path = base / "signing.crt.pem"
    leaf_cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    return Pki(ca_key, ca_cert, ca_cert_path, leaf_key_path, leaf_cert_path, leaf_cert)


def make_crl(pki: Pki, path: Path, *, revoke_leaf: bool) -> Path:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.ca_cert.subject)
        .last_update(_NOW - datetime.timedelta(hours=1))
        .next_update(_NOW + datetime.timedelta(days=30))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pki.ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    if revoke_leaf:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(pki.leaf_cert.serial_number)
            .revocation_date(_NOW - datetime.timedelta(minutes=30))
            .build()
        )
    crl = builder.sign(pki.ca_key, hashes.SHA256())
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return path


def _config(pki: Pki, **overrides: object) -> SigningConfig:
    values: dict[str, object] = {
        "policy": SigningPolicy.REQUIRED,
        "key_source": "pem",
        "key_path": pki.leaf_key_path,
        "cert_path": pki.leaf_cert_path,
        "detached_format": "cms",
        "trust_bundle_path": pki.ca_cert_path,
    }
    values.update(overrides)
    return SigningConfig.model_validate(values)


@pytest.fixture()
def pki(tmp_path: Path) -> Pki:
    return make_pki(tmp_path / "pki")


@pytest.fixture()
def report(tmp_path: Path) -> Path:
    path = tmp_path / "findings.sarif"
    path.write_text('{"version": "2.1.0", "runs": []}\n')
    return path


class TestCmsSignDetached:
    def test_cms_detached_roundtrip(self, pki: Pki, report: Path) -> None:
        p7s = sign_detached(report, _config(pki))
        assert p7s == report.parent / "findings.sarif.p7s"
        # DER-encoded ContentInfo starts with a SEQUENCE tag
        assert p7s.read_bytes()[0] == 0x30

        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[], revocation_mode="soft-fail"
        )
        assert isinstance(result, CmsVerifyResult)
        assert result.valid is True
        assert result.trusted is True
        assert result.intact is True
        assert "VAMS test signer" in result.signer_subject
        expected_fp = pki.leaf_cert.fingerprint(hashes.SHA256()).hex()
        assert result.signer_fp == f"sha256:{expected_fp}"

    def test_signature_does_not_embed_content(self, pki: Pki, report: Path) -> None:
        content = report.read_bytes()
        p7s = sign_detached(report, _config(pki))
        assert content not in p7s.read_bytes()

    @pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
    def test_openssl_cms_verify_accepts_sidecar(self, pki: Pki, report: Path) -> None:
        """Recipients verify with the documented openssl command line."""
        p7s = sign_detached(report, _config(pki))
        proc = subprocess.run(
            [
                "openssl",
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                str(p7s),
                "-content",
                str(report),
                "-CAfile",
                str(pki.ca_cert_path),
                "-purpose",
                "any",
                "-out",
                "/dev/null",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "Verification successful" in proc.stderr


class TestCmsVerifyDetached:
    def test_verify_untrusted_root_invalid(self, pki: Pki, report: Path, tmp_path: Path) -> None:
        other = make_pki(tmp_path / "other", cn="Some Other CA")
        p7s = sign_detached(report, _config(pki))
        result = verify_detached(
            report, p7s, trust_roots=[other.ca_cert_path], crls=[], revocation_mode="soft-fail"
        )
        assert result.intact is True
        assert result.trusted is False
        assert result.valid is False

    def test_verify_tampered_content_invalid(self, pki: Pki, report: Path) -> None:
        p7s = sign_detached(report, _config(pki))
        report.write_text('{"version": "2.1.0", "runs": ["tampered"]}\n')
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[], revocation_mode="soft-fail"
        )
        assert result.intact is False
        assert result.valid is False

    def test_verify_never_opens_socket(
        self, tmp_path: Path, report: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A leaf with an HTTP CRL distribution point must not trigger a fetch."""
        pki = make_pki(tmp_path / "dp", crl_dp=True)
        p7s = sign_detached(report, _config(pki))

        attempts: list[object] = []

        def _refuse(self: socket.socket, address: object) -> None:
            attempts.append(address)
            raise OSError("network access attempted during verification")

        monkeypatch.setattr(socket.socket, "connect", _refuse)
        monkeypatch.setattr(socket.socket, "connect_ex", _refuse)
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[], revocation_mode="soft-fail"
        )
        assert attempts == []
        assert result.intact is True
        assert result.valid is True

    def test_hard_fail_without_crl_is_invalid(self, tmp_path: Path, report: Path) -> None:
        pki = make_pki(tmp_path / "dp", crl_dp=True)
        p7s = sign_detached(report, _config(pki))
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[], revocation_mode="hard-fail"
        )
        assert result.intact is True
        assert result.valid is False

    def test_hard_fail_with_clean_crl_is_valid(self, tmp_path: Path, report: Path) -> None:
        pki = make_pki(tmp_path / "dp", crl_dp=True)
        crl = make_crl(pki, tmp_path / "ca.crl.pem", revoke_leaf=False)
        p7s = sign_detached(report, _config(pki))
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[crl], revocation_mode="hard-fail"
        )
        assert result.valid is True

    def test_revoked_signer_is_invalid(self, tmp_path: Path, report: Path) -> None:
        pki = make_pki(tmp_path / "dp", crl_dp=True)
        crl = make_crl(pki, tmp_path / "ca.crl.pem", revoke_leaf=True)
        p7s = sign_detached(report, _config(pki))
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[crl], revocation_mode="hard-fail"
        )
        assert result.intact is True
        assert result.valid is False

    def test_verify_garbage_p7s_is_invalid(self, pki: Pki, report: Path) -> None:
        p7s = report.parent / (report.name + ".p7s")
        p7s.write_bytes(b"not a cms structure")
        result = verify_detached(
            report, p7s, trust_roots=[pki.ca_cert_path], crls=[], revocation_mode="soft-fail"
        )
        assert result.valid is False
        assert result.error is not None


class TestReportSignerCms:
    def test_report_signer_verify_uses_p7s_sidecar(self, pki: Pki, report: Path) -> None:
        signer = ReportSigner.from_config(_config(pki))
        signed = signer.sign(report)
        assert signed.signed is True
        assert (report.parent / "findings.sarif.p7s").exists()
        assert not (report.parent / "findings.sarif.sig").exists()

        result = signer.verify(report)
        assert result.valid is True
        assert result.cert_fingerprint == signed.signer_fp

    def test_report_signer_verify_p7s_untrusted(
        self, pki: Pki, report: Path, tmp_path: Path
    ) -> None:
        ReportSigner.from_config(_config(pki)).sign(report)
        other = make_pki(tmp_path / "other", cn="Some Other CA")
        verifier = ReportSigner.from_config(_config(pki, trust_bundle_path=other.ca_cert_path))
        result = verifier.verify(report)
        assert result.valid is False
        assert result.error is not None
