"""Tests for SigningConfig resolution, signing policy and ReportSigner behaviour."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tarmo_vuln_core.signing import (
    ReportSigner,
    ReportSigningError,
    SigningConfig,
    SigningConfigError,
    SigningPolicy,
    SignResult,
)
from tarmo_vuln_core.signing.keygen import ensure_keys_exist

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_PDF = FIXTURES_DIR / "minimal.pdf"

_TARMO_ENV = (
    "TARMO_SIGNING_ENABLED",
    "TARMO_SIGNING_POLICY",
    "TARMO_SIGNING_KEY",
    "TARMO_SIGNING_CERT",
    "TARMO_SIGNING_P12",
    "TARMO_SIGNING_P12_PASS_FILE",
    "TARMO_SIGNING_KEY_SOURCE",
    "TARMO_SIGNING_TSA_URL",
    "TARMO_SIGNING_DETACHED_FORMAT",
    "TARMO_SIGNING_TRUST_BUNDLE",
    "TARMO_SIGNING_CRLS",
    "TARMO_SIGNING_REVOCATION_MODE",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _TARMO_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def dev_keys(tmp_path: Path) -> Path:
    key_dir = tmp_path / "keys"
    ensure_keys_exist(key_dir)
    return key_dir


def _pem_config(key_dir: Path, **overrides: object) -> SigningConfig:
    values: dict[str, object] = {
        "key_path": key_dir / "signing.key.pem",
        "cert_path": key_dir / "signing.cert.pem",
    }
    values.update(overrides)
    return SigningConfig.model_validate(values)


class TestSigningConfigDefaults:
    def test_default_enabled(self) -> None:
        cfg = SigningConfig()
        assert cfg.enabled is True

    def test_default_tsa_is_none(self) -> None:
        cfg = SigningConfig()
        assert cfg.tsa_url is None

    def test_default_tsa_is_none_from_env(self) -> None:
        cfg = SigningConfig.from_env()
        assert cfg.tsa_url is None

    def test_default_policy_best_effort(self) -> None:
        assert SigningConfig().policy is SigningPolicy.BEST_EFFORT
        assert SigningConfig.from_env().policy is SigningPolicy.BEST_EFFORT

    def test_default_detached_format_is_sig_json(self) -> None:
        assert SigningConfig().detached_format == "sig-json"

    def test_default_key_source_dev_selfsigned_without_key_vars(self) -> None:
        assert SigningConfig().key_source == "dev_selfsigned"
        assert SigningConfig.from_env().key_source == "dev_selfsigned"

    def test_key_paths_imply_pem_key_source(self, tmp_path: Path) -> None:
        cfg = SigningConfig(key_path=tmp_path / "k.pem", cert_path=tmp_path / "c.pem")
        assert cfg.key_source == "pem"

    def test_default_key_path_is_none(self) -> None:
        cfg = SigningConfig()
        assert cfg.key_path is None

    def test_default_cert_path_is_none(self) -> None:
        cfg = SigningConfig()
        assert cfg.cert_path is None


class TestSigningConfigEnvVars:
    def test_enabled_false_maps_to_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "false")
        cfg = SigningConfig.from_env()
        assert cfg.policy is SigningPolicy.OFF
        assert cfg.enabled is False

    def test_enabled_false_kwarg_maps_to_off(self) -> None:
        assert SigningConfig(enabled=False).policy is SigningPolicy.OFF

    def test_enabled_true_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "true")
        cfg = SigningConfig.from_env()
        assert cfg.enabled is True
        assert cfg.policy is SigningPolicy.BEST_EFFORT

    def test_policy_required_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_POLICY", "required")
        assert SigningConfig.from_env().policy is SigningPolicy.REQUIRED

    def test_invalid_policy_env_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_POLICY", "sometimes")
        with pytest.raises(SigningConfigError, match="TARMO_SIGNING_POLICY"):
            SigningConfig.from_env()

    def test_key_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        key = tmp_path / "my.key.pem"
        key.touch()
        monkeypatch.setenv("TARMO_SIGNING_KEY", str(key))
        cfg = SigningConfig.from_env()
        assert cfg.key_path == key
        assert cfg.key_source == "pem"

    def test_cert_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        cert = tmp_path / "my.cert.pem"
        cert.touch()
        monkeypatch.setenv("TARMO_SIGNING_CERT", str(cert))
        cfg = SigningConfig.from_env()
        assert cfg.cert_path == cert

    def test_p12_from_env_selects_pkcs12(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("TARMO_SIGNING_P12", str(tmp_path / "signing.p12"))
        monkeypatch.setenv("TARMO_SIGNING_P12_PASS_FILE", str(tmp_path / "signing.pass"))
        cfg = SigningConfig.from_env()
        assert cfg.key_source == "pkcs12"
        assert cfg.pkcs12_path == tmp_path / "signing.p12"
        assert cfg.pkcs12_pass_file == tmp_path / "signing.pass"

    def test_tsa_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_TSA_URL", "http://tsa.test.invalid/tsr")
        cfg = SigningConfig.from_env()
        assert cfg.tsa_url == "http://tsa.test.invalid/tsr"

    def test_trust_and_crls_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("TARMO_SIGNING_TRUST_BUNDLE", str(tmp_path / "bundle.pem"))
        monkeypatch.setenv("TARMO_SIGNING_CRLS", f"{tmp_path / 'a.crl'}:{tmp_path / 'b.crl'}")
        monkeypatch.setenv("TARMO_SIGNING_REVOCATION_MODE", "hard-fail")
        cfg = SigningConfig.from_env()
        assert cfg.trust_bundle_path == tmp_path / "bundle.pem"
        assert cfg.crl_paths == [tmp_path / "a.crl", tmp_path / "b.crl"]
        assert cfg.revocation_mode == "hard-fail"


class TestReportSignerDisabled:
    def test_sign_noop_when_disabled(self, tmp_path: Path) -> None:
        cfg = SigningConfig(enabled=False)
        signer = ReportSigner.from_config(cfg)
        target = tmp_path / "report.pdf"
        target.write_bytes(b"fake pdf content")
        result = signer.sign(target)
        assert result == SignResult(signed=False, signer_fp=None, tsa=False)
        assert target.read_bytes() == b"fake pdf content"
        assert not (tmp_path / "report.pdf.sig").exists()

    def test_sign_noop_leaves_no_sig_for_html(self, tmp_path: Path) -> None:
        cfg = SigningConfig(enabled=False)
        signer = ReportSigner.from_config(cfg)
        target = tmp_path / "report.html"
        target.write_text("<html/>")
        signer.sign(target)
        assert not (tmp_path / "report.html.sig").exists()

    def test_from_config_with_none_uses_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "false")
        signer = ReportSigner.from_config(None)
        target = tmp_path / "report.md"
        target.write_text("# r")
        assert signer.sign(target).signed is False
        assert not (tmp_path / "report.md.sig").exists()


class TestSigningPolicy:
    def test_required_policy_raises_on_missing_key(self, tmp_path: Path) -> None:
        cfg = SigningConfig(
            policy=SigningPolicy.REQUIRED,
            key_path=tmp_path / "missing.key.pem",
            cert_path=tmp_path / "missing.crt.pem",
        )
        with pytest.raises(SigningConfigError, match="missing.key.pem"):
            ReportSigner.from_config(cfg)

    def test_best_effort_missing_operator_key_never_generates(self, tmp_path: Path) -> None:
        operator_dir = tmp_path / "operator"
        operator_dir.mkdir()
        cfg = SigningConfig(
            key_path=operator_dir / "signing.key.pem",
            cert_path=operator_dir / "signing.cert.pem",
        )
        signer = ReportSigner.from_config(cfg)
        target = tmp_path / "report.md"
        target.write_text("# r")
        result = signer.sign(target)
        assert result.signed is False
        assert list(operator_dir.iterdir()) == []
        assert not (tmp_path / "report.md.sig").exists()

    def test_required_sign_failure_raises(self, dev_keys: Path, tmp_path: Path) -> None:
        signer = ReportSigner.from_config(_pem_config(dev_keys, policy=SigningPolicy.REQUIRED))
        bad_pdf = tmp_path / "bad.pdf"
        bad_pdf.write_bytes(b"this is not a pdf")
        with pytest.raises(ReportSigningError, match="bad.pdf"):
            signer.sign(bad_pdf)

    def test_per_call_policy_overrides_config(self, dev_keys: Path, tmp_path: Path) -> None:
        signer = ReportSigner.from_config(_pem_config(dev_keys))
        bad_pdf = tmp_path / "bad.pdf"
        bad_pdf.write_bytes(b"this is not a pdf")
        assert signer.sign(bad_pdf).signed is False
        with pytest.raises(ReportSigningError):
            signer.sign(bad_pdf, policy=SigningPolicy.REQUIRED)

    def test_required_unsignable_sig_json_extension_raises(
        self, dev_keys: Path, tmp_path: Path
    ) -> None:
        signer = ReportSigner.from_config(_pem_config(dev_keys, policy=SigningPolicy.REQUIRED))
        target = tmp_path / "findings.csv"
        target.write_text("id\n1\n")
        with pytest.raises(ReportSigningError, match="findings.csv"):
            signer.sign(target)

    def test_sign_result_reports_signer_fingerprint(self, dev_keys: Path, tmp_path: Path) -> None:
        signer = ReportSigner.from_config(_pem_config(dev_keys))
        target = tmp_path / "report.html"
        target.write_text("<html/>")
        result = signer.sign(target)
        cert = x509.load_pem_x509_certificate((dev_keys / "signing.cert.pem").read_bytes())
        assert result.signed is True
        assert result.signer_fp == f"sha256:{cert.fingerprint(hashes.SHA256()).hex()}"
        assert result.tsa is False

    def test_cms_format_routes_non_pdf_to_p7s(self, dev_keys: Path, tmp_path: Path) -> None:
        signer = ReportSigner.from_config(_pem_config(dev_keys, detached_format="cms"))
        target = tmp_path / "findings.csv"
        target.write_text("id,severity\n1,HIGH\n")
        result = signer.sign(target)
        assert result.signed is True
        assert (tmp_path / "findings.csv.p7s").exists()
        assert not (tmp_path / "findings.csv.sig").exists()

    def test_sign_never_opens_socket(
        self, dev_keys: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[object] = []

        def _refuse(self: socket.socket, address: object) -> None:
            attempts.append(address)
            raise OSError("network access attempted during signing")

        monkeypatch.setattr(socket.socket, "connect", _refuse)
        monkeypatch.setattr(socket.socket, "connect_ex", _refuse)

        pdf = tmp_path / "report.pdf"
        pdf.write_bytes(MINIMAL_PDF.read_bytes())
        html = tmp_path / "report.html"
        html.write_text("<html/>")
        csv = tmp_path / "findings.csv"
        csv.write_text("id\n1\n")

        sig_json = ReportSigner.from_config(_pem_config(dev_keys, policy=SigningPolicy.REQUIRED))
        cms = ReportSigner.from_config(
            _pem_config(dev_keys, policy=SigningPolicy.REQUIRED, detached_format="cms")
        )
        assert sig_json.sign(pdf).signed is True
        assert sig_json.sign(html).signed is True
        assert cms.sign(csv).signed is True
        assert attempts == []


class TestKeySources:
    def test_pkcs12_key_source_signs_and_verifies(self, dev_keys: Path, tmp_path: Path) -> None:
        key = serialization.load_pem_private_key(
            (dev_keys / "signing.key.pem").read_bytes(), password=None
        )
        cert = x509.load_pem_x509_certificate((dev_keys / "signing.cert.pem").read_bytes())
        p12 = tmp_path / "signing.p12"
        p12.write_bytes(
            pkcs12.serialize_key_and_certificates(
                b"signer",
                key,  # type: ignore[arg-type]
                cert,
                None,
                serialization.BestAvailableEncryption(b"s3cret-pass"),
            )
        )
        pass_file = tmp_path / "signing.pass"
        pass_file.write_text("s3cret-pass\n")

        cfg = SigningConfig(
            policy=SigningPolicy.REQUIRED,
            key_source="pkcs12",
            pkcs12_path=p12,
            pkcs12_pass_file=pass_file,
            trust_bundle_path=dev_keys / "signing.cert.pem",
            detached_format="cms",
        )
        signer = ReportSigner.from_config(cfg)
        pdf = tmp_path / "report.pdf"
        pdf.write_bytes(MINIMAL_PDF.read_bytes())
        sarif = tmp_path / "findings.sarif"
        sarif.write_text("{}")
        assert signer.sign(pdf).signed is True
        assert signer.sign(sarif).signed is True
        assert signer.verify(pdf).valid is True
        assert signer.verify(sarif).valid is True

    def test_pkcs12_wrong_passphrase_required_raises(self, dev_keys: Path, tmp_path: Path) -> None:
        key = serialization.load_pem_private_key(
            (dev_keys / "signing.key.pem").read_bytes(), password=None
        )
        cert = x509.load_pem_x509_certificate((dev_keys / "signing.cert.pem").read_bytes())
        p12 = tmp_path / "signing.p12"
        p12.write_bytes(
            pkcs12.serialize_key_and_certificates(
                b"signer",
                key,  # type: ignore[arg-type]
                cert,
                None,
                serialization.BestAvailableEncryption(b"right"),
            )
        )
        pass_file = tmp_path / "signing.pass"
        pass_file.write_text("wrong")
        cfg = SigningConfig(
            policy=SigningPolicy.REQUIRED,
            key_source="pkcs12",
            pkcs12_path=p12,
            pkcs12_pass_file=pass_file,
        )
        with pytest.raises(SigningConfigError, match="signing.p12"):
            ReportSigner.from_config(cfg)

    def test_pkcs11_key_source_refused(self) -> None:
        cfg = SigningConfig(policy=SigningPolicy.REQUIRED, key_source="pkcs11")
        with pytest.raises(SigningConfigError, match="pkcs11"):
            ReportSigner.from_config(cfg)

    def test_dev_selfsigned_generates_in_default_dir_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "tarmo_vuln_core.signing.config._DEFAULT_SIGNING_DIR", tmp_path / "dev-signing"
        )
        signer = ReportSigner.from_config(SigningConfig(policy=SigningPolicy.REQUIRED))
        assert (tmp_path / "dev-signing" / "signing.key.pem").exists()
        target = tmp_path / "report.md"
        target.write_text("# r")
        assert signer.sign(target).signed is True
