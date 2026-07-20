"""ECDSA P-256 detached .sig signing and verification for non-PDF formats."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from tarmo_vuln_core._compat import UTC
from tarmo_vuln_core.signing.config import SigningConfig

logger = logging.getLogger(__name__)

_SIGNABLE_EXTENSIONS = {".html", ".md", ".docx", ".pptx"}

# Formats explicitly excluded from signing
_EXCLUDED_EXTENSIONS = {".csv", ".json", ".sarif", ".xml"}


def sign_file(path: Path, config: SigningConfig) -> None:
    """Sign a non-PDF file by writing a JSON .sig sidecar.

    Skips silently for non-signable extensions. Never raises.
    """
    if path.suffix not in _SIGNABLE_EXTENSIONS:
        return

    try:
        _do_sign(path, config)
    except Exception:
        logger.warning("Failed to sign %s", path, exc_info=True)


def _do_sign(path: Path, config: SigningConfig) -> None:
    file_bytes = path.read_bytes()
    sha256_hex = hashlib.sha256(file_bytes).hexdigest()

    key_path = config.resolved_key_path()
    cert_path = config.resolved_cert_path()

    private_key = load_pem_private_key(key_path.read_bytes(), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey)

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    sig_bytes = private_key.sign(file_bytes, ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(sig_bytes).decode()

    now = datetime.datetime.now(UTC)

    envelope: dict[str, object] = {
        "version": 1,
        "algorithm": "ECDSA-P256-SHA256",
        "signed_at": now.isoformat().replace("+00:00", "Z"),
        "sha256": sha256_hex,
        "signature": sig_b64,
        "cert_fingerprint": f"sha256:{fingerprint}",
    }

    # Attempt RFC 3161 timestamp
    tsa_token = _get_tsa_token(sha256_hex, config.tsa_url)
    if tsa_token is not None:
        envelope["tsa_token"] = tsa_token

    sig_path = path.parent / (path.name + ".sig")
    sig_path.write_text(json.dumps(envelope, indent=2))


def _get_tsa_token(sha256_hex: str, tsa_url: str) -> str | None:
    """Request RFC 3161 timestamp. Returns base64-encoded token or None on failure."""
    try:
        import rfc3161ng

        digest = bytes.fromhex(sha256_hex)
        response = rfc3161ng.get_timestamp(digest, tsa_url, hash_algorithm="sha256")
        return base64.b64encode(response).decode()
    except Exception:
        logger.warning("TSA request failed for %s — signing without timestamp", tsa_url)
        return None


def verify_file(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    """Verify a detached .sig for a non-PDF file.

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

        # Enrich envelope with cert metadata for callers
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        cert_subject = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string()
        meta = dict(envelope)
        meta["cert_subject"] = cert_subject
        return True, None, meta

    except InvalidSignature:
        return False, "Signature verification failed — file may have been tampered with", envelope
    except Exception as exc:
        return False, f"Verification error: {exc}", envelope
