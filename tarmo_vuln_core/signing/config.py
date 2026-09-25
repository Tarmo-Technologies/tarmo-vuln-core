"""SigningConfig: Pydantic v2 model with env var resolution, policy and key material loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12
from pydantic import BaseModel, model_validator

from tarmo_vuln_core._compat import StrEnum

_DEFAULT_SIGNING_DIR = Path.home() / ".config" / "tarmo" / "signing"

KeySource = Literal["pkcs12", "pem", "pkcs11", "dev_selfsigned"]
DetachedFormat = Literal["sig-json", "cms"]
RevocationMode = Literal["hard-fail", "soft-fail"]

SigningKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey


class SigningError(Exception):
    """Base class for signing errors."""


class SigningConfigError(SigningError):
    """Signing configuration or key material is unusable."""


class ReportSigningError(SigningError):
    """A file could not be signed under the effective policy."""


class SigningPolicy(StrEnum):
    """What a signing failure means.

    ``REQUIRED``: any failure raises. ``BEST_EFFORT``: failures are logged and the
    file is left unsigned. ``OFF``: nothing is signed.
    """

    REQUIRED = "required"
    BEST_EFFORT = "best_effort"
    OFF = "off"


@dataclass(frozen=True)
class SigningMaterial:
    """A loaded signing key, its certificate and any extra chain certificates."""

    key: SigningKey
    cert: x509.Certificate
    chain: list[x509.Certificate] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return f"sha256:{self.cert.fingerprint(hashes.SHA256()).hex()}"


_FALSEY = ("false", "0", "no", "off")


def _env_path(name: str) -> Path | None:
    raw = os.environ.get(name)
    return Path(raw) if raw else None


class SigningConfig(BaseModel):
    """Signing configuration.

    The library default policy is ``BEST_EFFORT`` (fail open, logged), which keeps
    the historical contract for pentest-scribe. Callers that need fail-closed
    behaviour pass ``policy=SigningPolicy.REQUIRED`` explicitly.

    ``enabled`` is accepted as a legacy constructor argument: ``enabled=False``
    maps to ``policy=OFF``.
    """

    policy: SigningPolicy = SigningPolicy.BEST_EFFORT
    key_source: KeySource = "dev_selfsigned"
    key_path: Path | None = None
    cert_path: Path | None = None
    pkcs12_path: Path | None = None
    pkcs12_pass_file: Path | None = None
    tsa_url: str | None = None
    detached_format: DetachedFormat = "sig-json"
    trust_bundle_path: Path | None = None
    crl_paths: list[Path] = []
    revocation_mode: RevocationMode = "soft-fail"

    @model_validator(mode="before")
    @classmethod
    def _legacy_and_inferred_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        values = dict(data)
        if "enabled" in values:
            enabled = values.pop("enabled")
            if not enabled:
                values["policy"] = SigningPolicy.OFF
        if values.get("key_source") is None:
            values.pop("key_source", None)
            if values.get("pkcs12_path") is not None:
                values["key_source"] = "pkcs12"
            elif values.get("key_path") is not None or values.get("cert_path") is not None:
                values["key_source"] = "pem"
        return values

    @property
    def enabled(self) -> bool:
        return self.policy is not SigningPolicy.OFF

    @classmethod
    def from_env(cls) -> SigningConfig:
        """Resolve config from ``TARMO_SIGNING_*`` environment variables."""
        values: dict[str, Any] = {}

        policy_raw = os.environ.get("TARMO_SIGNING_POLICY")
        if policy_raw:
            try:
                values["policy"] = SigningPolicy(policy_raw.strip().lower())
            except ValueError as exc:
                allowed = ", ".join(p.value for p in SigningPolicy)
                raise SigningConfigError(
                    f"TARMO_SIGNING_POLICY={policy_raw!r} is not one of: {allowed}"
                ) from exc
        if os.environ.get("TARMO_SIGNING_ENABLED", "true").strip().lower() in _FALSEY:
            values["policy"] = SigningPolicy.OFF

        values["key_source"] = os.environ.get("TARMO_SIGNING_KEY_SOURCE") or None
        values["key_path"] = _env_path("TARMO_SIGNING_KEY")
        values["cert_path"] = _env_path("TARMO_SIGNING_CERT")
        values["pkcs12_path"] = _env_path("TARMO_SIGNING_P12")
        values["pkcs12_pass_file"] = _env_path("TARMO_SIGNING_P12_PASS_FILE")
        values["tsa_url"] = os.environ.get("TARMO_SIGNING_TSA_URL") or None
        values["trust_bundle_path"] = _env_path("TARMO_SIGNING_TRUST_BUNDLE")
        crls_raw = os.environ.get("TARMO_SIGNING_CRLS", "")
        values["crl_paths"] = [Path(p) for p in crls_raw.split(os.pathsep) if p]
        for env_name, key in (
            ("TARMO_SIGNING_DETACHED_FORMAT", "detached_format"),
            ("TARMO_SIGNING_REVOCATION_MODE", "revocation_mode"),
        ):
            raw = os.environ.get(env_name)
            if raw:
                values[key] = raw.strip().lower()
        try:
            return cls.model_validate(values)
        except ValueError as exc:
            raise SigningConfigError(f"invalid TARMO_SIGNING_* configuration: {exc}") from exc

    def resolved_key_path(self) -> Path:
        return self.key_path or (_DEFAULT_SIGNING_DIR / "signing.key.pem")

    def resolved_cert_path(self) -> Path:
        return self.cert_path or (_DEFAULT_SIGNING_DIR / "signing.cert.pem")

    def resolved_signing_dir(self) -> Path:
        return self.resolved_key_path().parent

    def load_material(self) -> SigningMaterial:
        """Load the signing key and certificate for the configured key source.

        Raises:
            SigningConfigError: the key source is unsupported, or the key material is
                missing, unreadable, of an unsupported type, or does not match its
                certificate.
        """
        if self.key_source == "pkcs11":
            raise SigningConfigError(
                "key_source 'pkcs11' is not supported by this build of tarmo-vuln-core"
            )
        material = self._load_pkcs12() if self.key_source == "pkcs12" else self._load_pem()
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if material.key.public_key().public_bytes(*spki) != material.cert.public_key().public_bytes(
            *spki
        ):
            raise SigningConfigError("signing key does not match the signing certificate")
        return material

    def _load_pem(self) -> SigningMaterial:
        key_path = self.resolved_key_path()
        cert_path = self.resolved_cert_path()
        try:
            key = load_pem_private_key(key_path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise SigningConfigError(f"cannot load signing key {key_path}: {exc}") from exc
        try:
            certs = x509.load_pem_x509_certificates(cert_path.read_bytes())
        except (OSError, ValueError) as exc:
            raise SigningConfigError(f"cannot load signing certificate {cert_path}: {exc}") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
            raise SigningConfigError(
                f"signing key {key_path} must be ECDSA or RSA, got {type(key).__name__}"
            )
        return SigningMaterial(key=key, cert=certs[0], chain=list(certs[1:]))

    def _load_pkcs12(self) -> SigningMaterial:
        if self.pkcs12_path is None:
            raise SigningConfigError("key_source 'pkcs12' requires pkcs12_path")
        password: bytes | None = None
        if self.pkcs12_pass_file is not None:
            try:
                password = self.pkcs12_pass_file.read_bytes().rstrip(b"\r\n")
            except OSError as exc:
                raise SigningConfigError(
                    f"cannot read PKCS#12 passphrase file {self.pkcs12_pass_file}: {exc}"
                ) from exc
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(
                self.pkcs12_path.read_bytes(), password
            )
        except (OSError, ValueError) as exc:
            raise SigningConfigError(
                f"cannot load PKCS#12 bundle {self.pkcs12_path}: {exc}"
            ) from exc
        if key is None or cert is None:
            raise SigningConfigError(
                f"PKCS#12 bundle {self.pkcs12_path} must contain a private key and certificate"
            )
        if not isinstance(key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
            raise SigningConfigError(
                f"PKCS#12 key in {self.pkcs12_path} must be ECDSA or RSA, got {type(key).__name__}"
            )
        return SigningMaterial(key=key, cert=cert, chain=list(extra))

    def load_trust_roots(self, material: SigningMaterial | None = None) -> list[x509.Certificate]:
        """Certificates trusted for verification.

        The operator trust bundle when configured; otherwise the configured signing
        certificate itself (self-signed ``dev_selfsigned`` and pentest-scribe keys).
        """
        if self.trust_bundle_path is not None:
            return load_certificates(self.trust_bundle_path)
        if material is not None:
            return [material.cert]
        return load_certificates(self.resolved_cert_path())[:1]


def load_certificates(path: Path) -> list[x509.Certificate]:
    """Load one or more certificates from a PEM bundle or a single DER file."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SigningConfigError(f"cannot read certificate file {path}: {exc}") from exc
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]
    except ValueError as exc:
        raise SigningConfigError(f"cannot parse certificate file {path}: {exc}") from exc
