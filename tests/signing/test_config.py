"""Tests for SigningConfig resolution and ReportSigner no-op behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.signing import ReportSigner, SigningConfig


class TestSigningConfigDefaults:
    def test_default_enabled(self) -> None:
        cfg = SigningConfig()
        assert cfg.enabled is True

    def test_default_tsa_url(self) -> None:
        cfg = SigningConfig()
        assert cfg.tsa_url == "https://freetsa.org/tsr"

    def test_default_key_path_is_none(self) -> None:
        cfg = SigningConfig()
        assert cfg.key_path is None

    def test_default_cert_path_is_none(self) -> None:
        cfg = SigningConfig()
        assert cfg.cert_path is None


class TestSigningConfigEnvVars:
    def test_enabled_false_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "false")
        cfg = SigningConfig.from_env()
        assert cfg.enabled is False

    def test_enabled_true_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "true")
        cfg = SigningConfig.from_env()
        assert cfg.enabled is True

    def test_key_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        key = tmp_path / "my.key.pem"
        key.touch()
        monkeypatch.setenv("TARMO_SIGNING_KEY", str(key))
        cfg = SigningConfig.from_env()
        assert cfg.key_path == key

    def test_cert_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        cert = tmp_path / "my.cert.pem"
        cert.touch()
        monkeypatch.setenv("TARMO_SIGNING_CERT", str(cert))
        cfg = SigningConfig.from_env()
        assert cfg.cert_path == cert

    def test_tsa_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_TSA_URL", "https://custom.tsa.example/tsr")
        cfg = SigningConfig.from_env()
        assert cfg.tsa_url == "https://custom.tsa.example/tsr"


class TestReportSignerDisabled:
    def test_sign_noop_when_disabled(self, tmp_path: Path) -> None:
        cfg = SigningConfig(enabled=False)
        signer = ReportSigner.from_config(cfg)
        target = tmp_path / "report.pdf"
        target.write_bytes(b"fake pdf content")
        signer.sign(target)
        # File unchanged, no .sig created
        assert target.read_bytes() == b"fake pdf content"
        assert not (tmp_path / "report.pdf.sig").exists()

    def test_sign_noop_leaves_no_sig_for_html(self, tmp_path: Path) -> None:
        cfg = SigningConfig(enabled=False)
        signer = ReportSigner.from_config(cfg)
        target = tmp_path / "report.html"
        target.write_text("<html/>")
        signer.sign(target)
        assert not (tmp_path / "report.html.sig").exists()

    def test_from_config_with_none_uses_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_SIGNING_ENABLED", "false")
        signer = ReportSigner.from_config(None)
        # Should not raise; returns a no-op signer
        assert signer is not None
