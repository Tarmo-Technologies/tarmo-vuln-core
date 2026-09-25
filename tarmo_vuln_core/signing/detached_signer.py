"""ECDSA P-256 detached ``.sig`` JSON signing and verification for non-PDF formats.

The ``sig-json`` envelope is kept for pentest-scribe and for verifying existing
``.sig`` files. New consumers that need recipients to verify with standard tools
use the CMS ``.p7s`` sidecar (:mod:`tarmo_vuln_core.signing.cms_signer`).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from tarmo_vuln_core._compat import UTC
from tarmo_vuln_core.signing.config import (
    ReportSigningError,
    SigningConfig,
    SigningPolicy,
)

logger = logging.getLogger(__name__)

SIGNABLE_EXTENSIONS = frozenset({".html", ".md", ".docx", ".pptx"})
_SIGNABLE_EXTENSIONS = SIGNABLE_EXTENSIONS  # backward-compatible alias

# Formats explicitly excluded from sig-json signing
_EXCLUDED_EXTENSIONS = {".csv", ".json", ".sarif", ".xml"}


@dataclass(frozen=True)
class DetachedSignOutcome:
    sig_path: Path
    signer_fp: str
    tsa: bool


def sign_file(
    path: Path, config: SigningConfig, *, policy: SigningPolicy | None = None
) -> DetachedSignOutcome:
    """Sign a non-PDF file by writing a JSON ``<path>.sig`` sidecar.

    Raises:
        ReportSigningError: the extension is not signable in sig-json, the key is not
            ECDSA, or (under ``REQUIRED``) the configured TSA fails.
        SigningConfigError: the key material cannot be loaded.
    """
    effective = policy or config.policy
    if path.suffix not in SIGNABLE_EXTENSIONS:
        raise ReportSigningError(
            f"{path.name}: extension {path.suffix!r} is not signable with the sig-json "
            "envelope; use detached_format='cms'"
        )

    material = config.load_material()
    if not isinstance(material.key, EllipticCurvePrivateKey):
        raise ReportSigningError(
            f"{path.name}: the sig-json envelope supports only ECDSA P-256 keys; "
            "use detached_format='cms' for RSA keys"
        )

    file_bytes = path.read_bytes()
    sha256_hex = hashlib.sha256(file_bytes).hexdigest()
    sig_bytes = material.key.sign(file_bytes, ECDSA(hashes.SHA256()))

    envelope: dict[str, object] = {
        "version": 1,
        "algorithm": "ECDSA-P256-SHA256",
        "signed_at": datetime.datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "sha256": sha256_hex,
        "signature": base64.b64encode(sig_bytes).decode(),
        "cert_fingerprint": material.fingerprint,
        "tsa": None,
    }

    tsa_token = _get_tsa_token(sha256_hex, config.tsa_url, effective)
    if tsa_token is not None:
        envelope["tsa"] = config.tsa_url
        envelope["tsa_token"] = tsa_token

    sig_path = path.parent / (path.name + ".sig")
    tmp_path = sig_path.with_name(f".{sig_path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(json.dumps(envelope, indent=2))
    os.replace(tmp_path, sig_path)
    return DetachedSignOutcome(
        sig_path=sig_path, signer_fp=material.fingerprint, tsa=tsa_token is not None
    )


def _get_tsa_token(sha256_hex: str, tsa_url: str | None, policy: SigningPolicy) -> str | None:
    """Request an RFC 3161 timestamp token for ``sha256_hex``.

    No request is made when ``tsa_url`` is ``None``. On a TSA failure,
    ``REQUIRED`` raises :class:`ReportSigningError`; ``BEST_EFFORT`` logs a warning
    and returns ``None``.
    """
    if tsa_url is None:
        return None

    import rfc3161ng
    from pyasn1.error import PyAsn1Error  # type: ignore[import-untyped]

    try:
        stamper = rfc3161ng.RemoteTimestamper(tsa_url, hashname="sha256")
        token: bytes = stamper.timestamp(digest=bytes.fromhex(sha256_hex))
    except (
        rfc3161ng.TimestampingError,
        OSError,  # includes requests.RequestException
        ValueError,
        PyAsn1Error,
    ) as exc:
        if policy is SigningPolicy.REQUIRED:
            raise ReportSigningError(f"TSA request to {tsa_url} failed: {exc}") from exc
        logger.warning(
            "TSA request to %s failed; recording tsa=null in the envelope", tsa_url, exc_info=True
        )
        return None
    return base64.b64encode(token).decode()


def verify_file(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    """Verify a detached ``.sig`` for a non-PDF file.

    Returns (valid, error_message, metadata_dict).
    """
    sig_path = path.parent / (path.name + ".sig")

    if not sig_path.exists():
        return False, f"No .sig file found at {sig_path}", {}

    try:
        envelope = json.loads(sig_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"Cannot read .sig file: {exc}", {}

    try:
        file_bytes = path.read_bytes()
        actual_sha256 = hashlib.sha256(file_bytes).hexdigest()

        if actual_sha256 != envelope.get("sha256"):
            return False, "SHA-256 mismatch — file has been modified", envelope

        cert_path = config.resolved_cert_path()
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        public_key = cert.public_key()
        if not isinstance(public_key, EllipticCurvePublicKey):
            return False, "Signing cert does not use an elliptic curve key", envelope

        sig_bytes = base64.b64decode(envelope["signature"])
        public_key.verify(sig_bytes, file_bytes, ECDSA(hashes.SHA256()))

        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        cert_subject = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string()
        meta = dict(envelope)
        meta["cert_subject"] = cert_subject
        return True, None, meta

    except InvalidSignature:
        return False, "Signature verification failed — file may have been tampered with", envelope
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f"Verification error: {exc}", envelope
