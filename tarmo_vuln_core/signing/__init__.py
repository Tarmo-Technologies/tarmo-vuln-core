"""Report signing and verification for pentest-scribe, VAMS and other consumers.

Policy (``SigningConfig.policy``):

- ``REQUIRED``: :meth:`ReportSigner.from_config` raises :class:`SigningConfigError`
  when the key material is unusable, and :meth:`ReportSigner.sign` raises
  :class:`ReportSigningError` whenever a file is not signed.
- ``BEST_EFFORT`` (library default): failures are logged with a traceback and
  :meth:`ReportSigner.sign` returns ``SignResult(signed=False)``.
- ``OFF``: nothing is signed.

No network request is made unless ``tsa_url`` is configured.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from tarmo_vuln_core.signing.config import (
    ReportSigningError,
    SigningConfig,
    SigningConfigError,
    SigningError,
    SigningMaterial,
    SigningPolicy,
)
from tarmo_vuln_core.signing.keygen import ensure_keys_exist

logger = logging.getLogger(__name__)

_PDF_EXTENSIONS = {".pdf"}
_DETACHED_EXTENSIONS = {".html", ".md", ".docx", ".pptx"}
_SIGNABLE_EXTENSIONS = _PDF_EXTENSIONS | _DETACHED_EXTENSIONS


class SignResult(BaseModel):
    """What :meth:`ReportSigner.sign` did.

    ``signer_fp`` is ``"sha256:<hex>"`` of the signing certificate; ``tsa`` is true
    when an RFC 3161 timestamp was embedded.
    """

    signed: bool
    signer_fp: str | None = None
    tsa: bool = False


_UNSIGNED = SignResult(signed=False, signer_fp=None, tsa=False)


class VerificationResult(BaseModel):
    path: Path
    valid: bool
    signed_at: datetime | None = None
    cert_subject: str | None = None
    cert_fingerprint: str | None = None
    has_timestamp: bool = False
    error: str | None = None


class ReportSigner:
    """Signs and verifies report files.

    PDF files are signed in place with an embedded PAdES signature. Other files get
    a detached sidecar: CMS ``<file>.p7s`` when ``detached_format == "cms"``
    (any extension), otherwise the JSON ``<file>.sig`` envelope (``.html``, ``.md``,
    ``.docx``, ``.pptx`` only).
    """

    def __init__(self, config: SigningConfig) -> None:
        self._config = config
        self._material: SigningMaterial | None = None

    @property
    def config(self) -> SigningConfig:
        return self._config

    @classmethod
    def from_config(cls, config: SigningConfig | None = None) -> ReportSigner:
        """Create a ReportSigner, resolving ``config`` from the environment when None.

        Under ``dev_selfsigned`` a keypair is generated in the default signing
        directory on first use. Keys are never generated for an operator key
        source.

        Raises:
            SigningConfigError: under ``REQUIRED``, when the key material is missing
                or unusable.
        """
        if config is None:
            config = SigningConfig.from_env()

        signer = cls(config)
        if config.policy is SigningPolicy.OFF:
            return signer

        try:
            if config.key_source == "dev_selfsigned":
                ensure_keys_exist(config.resolved_signing_dir())
            signer._material = config.load_material()
        except SigningConfigError:
            if config.policy is SigningPolicy.REQUIRED:
                raise
            logger.warning(
                "Signing key material unavailable (key_source=%s); files will be left unsigned",
                config.key_source,
                exc_info=True,
            )
        return signer

    def _signable(self, path: Path) -> bool:
        if path.suffix in _PDF_EXTENSIONS:
            return True
        if self._config.detached_format == "cms":
            return True
        return path.suffix in _DETACHED_EXTENSIONS

    def sign(self, path: Path, *, policy: SigningPolicy | None = None) -> SignResult:
        """Sign ``path`` according to the effective policy.

        ``policy`` overrides the config's policy for this call.

        Raises:
            ReportSigningError: under ``REQUIRED``, whenever the file is not signed.
        """
        effective = policy or self._config.policy
        if effective is SigningPolicy.OFF:
            return _UNSIGNED

        if not self._signable(path):
            if effective is SigningPolicy.REQUIRED:
                raise ReportSigningError(
                    f"{path.name}: extension {path.suffix!r} is not signable with the "
                    f"{self._config.detached_format} format"
                )
            return _UNSIGNED

        try:
            return self._sign(path, effective)
        except Exception as exc:  # policy decides: pyHanko, cryptography, OS and our own errors
            return self._handle_failure(path, effective, exc)

    def _handle_failure(self, path: Path, policy: SigningPolicy, exc: Exception) -> SignResult:
        if policy is SigningPolicy.REQUIRED:
            if isinstance(exc, ReportSigningError):
                raise exc
            raise ReportSigningError(f"failed to sign {path.name}: {exc}") from exc
        logger.warning("Failed to sign %s; leaving it unsigned", path, exc_info=exc)
        return _UNSIGNED

    def _sign(self, path: Path, policy: SigningPolicy) -> SignResult:
        material = self._material or self._config.load_material()
        self._material = material
        if path.suffix in _PDF_EXTENSIONS:
            from tarmo_vuln_core.signing.pdf_signer import sign_pdf

            outcome = sign_pdf(path, self._config, policy=policy, material=material)
            return SignResult(signed=True, signer_fp=outcome.signer_fp, tsa=outcome.tsa)
        if self._config.detached_format == "cms":
            from tarmo_vuln_core.signing.cms_signer import sign_detached

            sign_detached(path, self._config, material=material)
            return SignResult(signed=True, signer_fp=material.fingerprint, tsa=False)

        from tarmo_vuln_core.signing.detached_signer import sign_file

        detached = sign_file(path, self._config, policy=policy)
        return SignResult(signed=True, signer_fp=detached.signer_fp, tsa=detached.tsa)

    def verify(self, path: Path) -> VerificationResult:
        """Verify a signed report file.

        PDF: every embedded PAdES signature. Other files: the ``<file>.p7s`` CMS
        sidecar when present, otherwise the ``<file>.sig`` JSON envelope.
        Returns ``valid=False`` with ``error`` set on any failure.
        """
        if path.suffix in _PDF_EXTENSIONS:
            return self._verify_pdf(path)
        from tarmo_vuln_core.signing.cms_signer import p7s_path_for

        if p7s_path_for(path).exists():
            return self._verify_cms(path)
        return self._verify_detached(path)

    def _verify_pdf(self, path: Path) -> VerificationResult:
        from tarmo_vuln_core.signing.pdf_signer import verify_pdf

        valid, error, meta = verify_pdf(path, self._config)
        return VerificationResult(
            path=path,
            valid=valid,
            error=error,
            cert_subject=str(meta.get("cert_subject")) if meta.get("cert_subject") else None,
            cert_fingerprint=str(meta.get("cert_fingerprint"))
            if meta.get("cert_fingerprint")
            else None,
            has_timestamp=bool(meta.get("has_timestamp", False)),
        )

    def _verify_cms(self, path: Path) -> VerificationResult:
        from tarmo_vuln_core.signing.cms_signer import p7s_path_for, verify_detached

        try:
            roots = self._config.load_trust_roots(self._material)
        except SigningConfigError as exc:
            return VerificationResult(path=path, valid=False, error=str(exc))
        result = verify_detached(
            path,
            p7s_path_for(path),
            trust_roots=roots,
            crls=self._config.crl_paths,
            revocation_mode=self._config.revocation_mode,
        )
        signed_at: datetime | None = None
        if result.signed_at:
            with contextlib.suppress(ValueError):
                signed_at = datetime.fromisoformat(result.signed_at)
        return VerificationResult(
            path=path,
            valid=result.valid,
            error=result.error,
            signed_at=signed_at,
            cert_subject=result.signer_subject,
            cert_fingerprint=result.signer_fp,
        )

    def _verify_detached(self, path: Path) -> VerificationResult:
        from tarmo_vuln_core.signing.detached_signer import verify_file

        valid, error, meta = verify_file(path, self._config)

        signed_at: datetime | None = None
        if meta.get("signed_at"):
            with contextlib.suppress(ValueError):
                signed_at = datetime.fromisoformat(str(meta["signed_at"]).replace("Z", "+00:00"))

        return VerificationResult(
            path=path,
            valid=valid,
            error=error,
            signed_at=signed_at,
            cert_subject=str(meta.get("cert_subject")) if meta.get("cert_subject") else None,
            cert_fingerprint=str(meta.get("cert_fingerprint"))
            if meta.get("cert_fingerprint")
            else None,
            has_timestamp="tsa_token" in meta,
        )


__all__ = [
    "ReportSigner",
    "ReportSigningError",
    "SignResult",
    "SigningConfig",
    "SigningConfigError",
    "SigningError",
    "SigningPolicy",
    "VerificationResult",
]
