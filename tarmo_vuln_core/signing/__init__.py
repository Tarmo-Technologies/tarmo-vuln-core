"""Report signing and verification for pentest-scribe and other downstream consumers."""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from tarmo_vuln_core.signing.config import SigningConfig
from tarmo_vuln_core.signing.keygen import ensure_keys_exist

logger = logging.getLogger(__name__)

_PDF_EXTENSIONS = {".pdf"}
_DETACHED_EXTENSIONS = {".html", ".md", ".docx", ".pptx"}
_SIGNABLE_EXTENSIONS = _PDF_EXTENSIONS | _DETACHED_EXTENSIONS


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

    PDF files are signed in-place with PAdES-T (embedded PAdES + RFC 3161 timestamp).
    Non-PDF signable files (.html, .md, .docx, .pptx) get a JSON .sig sidecar.

    sign() never raises — logs warnings and returns on any failure.
    """

    def __init__(self, config: SigningConfig) -> None:
        self._config = config

    @classmethod
    def from_config(cls, config: SigningConfig | None = None) -> ReportSigner:
        """Create a ReportSigner from config.

        If config is None, resolves from environment variables.
        Auto-generates signing keypair on first use if signing is enabled.
        """
        if config is None:
            config = SigningConfig.from_env()

        if config.enabled:
            signing_dir = config.resolved_signing_dir()
            try:
                ensure_keys_exist(signing_dir)
            except Exception:
                logger.warning(
                    "Could not ensure signing keys exist at %s — signing will be skipped",
                    signing_dir,
                    exc_info=True,
                )

        return cls(config)

    def sign(self, path: Path) -> None:
        """Sign a report file.

        PDF → PAdES-T in-place.
        HTML/MD/DOCX/PPTX → detached ECDSA .sig sidecar.
        All other extensions → silently skipped.
        Never raises.
        """
        if not self._config.enabled:
            return

        if path.suffix not in _SIGNABLE_EXTENSIONS:
            return

        if path.suffix in _PDF_EXTENSIONS:
            from tarmo_vuln_core.signing.pdf_signer import sign_pdf

            sign_pdf(path, self._config)
        else:
            from tarmo_vuln_core.signing.detached_signer import sign_file

            sign_file(path, self._config)

    def verify(self, path: Path) -> VerificationResult:
        """Verify a signed report file.

        PDF → checks embedded PAdES signature.
        Non-PDF → checks .sig sidecar file.
        Returns VerificationResult with valid=False and error set on any failure.
        """
        if path.suffix in _PDF_EXTENSIONS:
            return self._verify_pdf(path)
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


__all__ = ["ReportSigner", "SigningConfig", "VerificationResult"]
