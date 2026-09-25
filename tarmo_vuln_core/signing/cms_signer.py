"""CMS (PKCS#7) detached signatures written as ``<file>.p7s`` sidecars.

Signing uses ``cryptography``'s ``PKCS7SignatureBuilder`` (DER, SHA-256,
detached, binary). ``cryptography`` has no public CMS verify, so verification
uses pyHanko's ``async_validate_detached_cms`` with a ``ValidationContext`` that
never fetches revocation data or certificates over the network.

Recipients can verify without this library::

    openssl cms -verify -binary -inform DER -content <file> -in <file>.p7s \\
        -CAfile <trust-bundle.pem>
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
from collections.abc import Coroutine, Sequence
from pathlib import Path
from typing import Any, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from pydantic import BaseModel

from tarmo_vuln_core.signing.config import (
    RevocationMode,
    SigningConfig,
    SigningConfigError,
    SigningMaterial,
    load_certificates,
)

logger = logging.getLogger(__name__)

P7S_SUFFIX = ".p7s"

_T = TypeVar("_T")


class CmsVerifyResult(BaseModel):
    """Outcome of verifying a CMS detached signature.

    ``valid`` is true only when the signature is intact, cryptographically valid
    and chains to a configured trust root.
    """

    valid: bool
    trusted: bool = False
    intact: bool = False
    signer_subject: str | None = None
    signer_fp: str | None = None
    signed_at: str | None = None
    error: str | None = None


def p7s_path_for(path: Path) -> Path:
    return path.parent / (path.name + P7S_SUFFIX)


def sign_detached(
    path: Path, config: SigningConfig, *, material: SigningMaterial | None = None
) -> Path:
    """Write a DER CMS detached signature for ``path`` to ``<path>.p7s``.

    Raises:
        SigningConfigError: the key material cannot be loaded.
        OSError: the input cannot be read or the sidecar cannot be written.
    """
    material = material or config.load_material()
    data = path.read_bytes()
    builder = pkcs7.PKCS7SignatureBuilder().set_data(data)
    builder = builder.add_signer(material.cert, material.key, hashes.SHA256())
    for extra in material.chain:
        builder = builder.add_certificate(extra)
    der = builder.sign(
        serialization.Encoding.DER,
        [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
    )
    p7s = p7s_path_for(path)
    tmp = p7s.with_name(f".{p7s.name}.{os.getpid()}.tmp")
    tmp.write_bytes(der)
    os.replace(tmp, p7s)
    return p7s


def _load_crl_der(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SigningConfigError(f"cannot read CRL file {path}: {exc}") from exc
    try:
        crl = (
            x509.load_pem_x509_crl(data) if b"-----BEGIN" in data else x509.load_der_x509_crl(data)
        )
    except ValueError as exc:
        raise SigningConfigError(f"cannot parse CRL file {path}: {exc}") from exc
    return crl.public_bytes(serialization.Encoding.DER)


def _trust_root_ders(trust_roots: Sequence[Path | x509.Certificate]) -> list[bytes]:
    ders: list[bytes] = []
    for root in trust_roots:
        certs = load_certificates(root) if isinstance(root, Path) else [root]
        ders.extend(c.public_bytes(serialization.Encoding.DER) for c in certs)
    return ders


def run_coroutine_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to completion, also when called from inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def build_validation_context(
    trust_roots: Sequence[Path | x509.Certificate],
    crls: Sequence[Path],
    revocation_mode: RevocationMode,
) -> Any:
    """A pyHanko ``ValidationContext`` that never fetches over the network."""
    from asn1crypto import crl as asn1_crl
    from asn1crypto import x509 as asn1_x509
    from pyhanko_certvalidator import ValidationContext

    return ValidationContext(
        trust_roots=[asn1_x509.Certificate.load(d) for d in _trust_root_ders(trust_roots)],
        crls=[asn1_crl.CertificateList.load(_load_crl_der(p)) for p in crls],
        allow_fetching=False,
        revocation_mode=revocation_mode,
    )


def verify_detached(
    path: Path,
    p7s: Path,
    *,
    trust_roots: Sequence[Path | x509.Certificate],
    crls: Sequence[Path] = (),
    revocation_mode: RevocationMode = "hard-fail",
) -> CmsVerifyResult:
    """Verify the CMS detached signature ``p7s`` over ``path``.

    Never opens a network connection. Any parse or validation failure yields
    ``valid=False`` with ``error`` set.
    """
    try:
        return _verify(path, p7s, trust_roots, crls, revocation_mode)
    except SigningConfigError as exc:
        return CmsVerifyResult(valid=False, error=str(exc))
    except Exception as exc:  # verification fails closed on any error
        logger.debug("CMS verification of %s failed", path, exc_info=True)
        return CmsVerifyResult(valid=False, error=f"CMS verification error: {exc}")


def _verify(
    path: Path,
    p7s: Path,
    trust_roots: Sequence[Path | x509.Certificate],
    crls: Sequence[Path],
    revocation_mode: RevocationMode,
) -> CmsVerifyResult:
    from asn1crypto import cms
    from pyhanko.sign.validation.generic_cms import async_validate_detached_cms

    if not p7s.exists():
        return CmsVerifyResult(valid=False, error=f"No .p7s file found at {p7s}")
    content_info = cms.ContentInfo.load(p7s.read_bytes())
    if content_info["content_type"].native != "signed_data":
        return CmsVerifyResult(valid=False, error=f"{p7s.name} is not a CMS SignedData structure")
    signed_data = content_info["content"]
    if signed_data["encap_content_info"]["content"].native is not None:
        return CmsVerifyResult(valid=False, error=f"{p7s.name} is not a detached signature")

    vc = build_validation_context(trust_roots, crls, revocation_mode)
    with path.open("rb") as fh:
        status = run_coroutine_sync(
            async_validate_detached_cms(fh, signed_data, signer_validation_context=vc)
        )

    cert = status.signing_cert
    intact = bool(status.intact)
    crypto_valid = bool(status.valid)
    trusted = bool(status.trusted)
    valid = intact and crypto_valid and trusted and bool(status.bottom_line)
    reasons: list[str] = []
    if not intact:
        reasons.append("content does not match the signature")
    if not crypto_valid:
        reasons.append("signature cryptographically invalid")
    if not trusted:
        reasons.append("signer certificate not trusted or revoked")
    signed_at = status.signer_reported_dt.isoformat() if status.signer_reported_dt else None
    return CmsVerifyResult(
        valid=valid,
        trusted=trusted,
        intact=intact,
        signer_subject=str(cert.subject.human_friendly) if cert is not None else None,
        signer_fp=f"sha256:{cert.sha256.hex()}" if cert is not None else None,
        signed_at=signed_at,
        error=None if valid else ("; ".join(reasons) or "signature invalid"),
    )
