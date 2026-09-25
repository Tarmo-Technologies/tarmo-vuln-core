"""Tests for ECDSA keypair and self-signed cert auto-generation."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from tarmo_vuln_core.signing import SigningConfigError
from tarmo_vuln_core.signing.keygen import ensure_keys_exist


class TestKeygenGeneration:
    def test_generates_key_file(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        assert (tmp_path / "signing.key.pem").exists()

    def test_generates_cert_pem_file(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        assert (tmp_path / "signing.cert.pem").exists()

    def test_generates_cert_der_file(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        assert (tmp_path / "signing.cert.der").exists()

    def test_key_is_ecdsa_p256(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        key_bytes = (tmp_path / "signing.key.pem").read_bytes()
        key = load_pem_private_key(key_bytes, password=None)
        assert isinstance(key, EllipticCurvePrivateKey)
        assert key.key_size == 256

    def test_key_file_permissions_0600(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        key_path = tmp_path / "signing.key.pem"
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_cert_subject_default_cn(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        cert_bytes = (tmp_path / "signing.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "Tarmo Report Signer"

    def test_cert_subject_custom_cn(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNER_CN", "Acme Pentesting LLC")
        ensure_keys_exist(tmp_path)
        cert_bytes = (tmp_path / "signing.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "Acme Pentesting LLC"

    def test_cert_subject_custom_org(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNER_ORG", "Acme Security")
        ensure_keys_exist(tmp_path)
        cert_bytes = (tmp_path / "signing.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        org_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        assert len(org_attrs) == 1
        assert org_attrs[0].value == "Acme Security"

    def test_cert_der_matches_pem(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        cert_pem = x509.load_pem_x509_certificate((tmp_path / "signing.cert.pem").read_bytes())
        cert_der = x509.load_der_x509_certificate((tmp_path / "signing.cert.der").read_bytes())
        assert cert_pem.fingerprint(cert_pem.signature_hash_algorithm) == cert_der.fingerprint(  # type: ignore[arg-type]
            cert_der.signature_hash_algorithm  # type: ignore[arg-type]
        )

    def test_idempotent_does_not_regenerate(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        key_mtime_1 = (tmp_path / "signing.key.pem").stat().st_mtime
        ensure_keys_exist(tmp_path)
        key_mtime_2 = (tmp_path / "signing.key.pem").stat().st_mtime
        assert key_mtime_1 == key_mtime_2, "Key was regenerated on second call"


class TestKeygenFileSafety:
    def test_keygen_mode_0600_under_umask_022(self, tmp_path: Path) -> None:
        key_dir = tmp_path / "fresh" / "signing"
        old = os.umask(0o022)
        try:
            ensure_keys_exist(key_dir)
        finally:
            os.umask(old)
        assert stat.S_IMODE(key_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((key_dir / "signing.key.pem").stat().st_mode) == 0o600

    def test_key_file_created_with_o_excl_0600(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, int, int]] = []
        real_open = os.open

        def _spy(path: str | os.PathLike[str], flags: int, mode: int = 0o777, **kw: object) -> int:
            calls.append((os.fspath(path), flags, mode))
            return real_open(path, flags, mode, **kw)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "open", _spy)
        ensure_keys_exist(tmp_path)
        key_calls = [c for c in calls if c[0].endswith("signing.key.pem")]
        assert len(key_calls) == 1
        _, flags, mode = key_calls[0]
        assert flags & os.O_EXCL
        assert flags & os.O_CREAT
        assert mode == 0o600

    def test_keygen_refuses_preplanted_symlink(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim.txt"
        victim.write_text("do not overwrite")
        key_dir = tmp_path / "signing"
        key_dir.mkdir()
        (key_dir / "signing.key.pem").symlink_to(victim)
        with pytest.raises(SigningConfigError):
            ensure_keys_exist(key_dir)
        assert victim.read_text() == "do not overwrite"

    def test_keygen_refuses_partial_key_material(self, tmp_path: Path) -> None:
        ensure_keys_exist(tmp_path)
        (tmp_path / "signing.cert.der").unlink()
        key_before = (tmp_path / "signing.key.pem").read_bytes()
        with pytest.raises(SigningConfigError, match="signing.cert.der"):
            ensure_keys_exist(tmp_path)
        assert (tmp_path / "signing.key.pem").read_bytes() == key_before

    @pytest.mark.parametrize("marker", ["signing.p12", "local-ca.json"])
    def test_keygen_refuses_operator_key_directory(self, tmp_path: Path, marker: str) -> None:
        (tmp_path / marker).write_bytes(b"operator material")
        with pytest.raises(SigningConfigError, match=marker):
            ensure_keys_exist(tmp_path)
        assert not (tmp_path / "signing.key.pem").exists()
