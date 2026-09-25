"""PAdES PDF signing and verification via pyHanko.

A timestamp (PAdES-B-T) is requested only when ``config.tsa_url`` is set. Under
``REQUIRED`` a TSA failure raises and the file is left untouched; it is never
silently downgraded to PAdES-B-B. Under ``BEST_EFFORT`` the downgrade is logged.
"""

from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from tarmo_vuln_core.signing.cms_signer import build_validation_context, run_coroutine_sync
from tarmo_vuln_core.signing.config import (
    ReportSigningError,
    SigningConfig,
    SigningConfigError,
    SigningMaterial,
    SigningPolicy,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PdfSignOutcome:
    signer_fp: str
    tsa: bool


def _pyhanko_signer(material: SigningMaterial) -> Any:
    from asn1crypto import keys as asn1_keys
    from asn1crypto import x509 as asn1_x509
    from pyhanko.sign.signers import SimpleSigner
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    signing_cert = asn1_x509.Certificate.load(
        material.cert.public_bytes(serialization.Encoding.DER)
    )
    signing_key = asn1_keys.PrivateKeyInfo.load(
        material.key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    chain = [
        asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))
        for c in material.chain
    ]
    return SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=SimpleCertificateStore.from_certs([signing_cert, *chain]),
    )


def _sign_bytes(pdf_bytes: bytes, signer: Any, timestamper: Any) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.signers import PdfSignatureMetadata
    from pyhanko.sign.signers import sign_pdf as pyhanko_sign_pdf

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))
    out_buf = io.BytesIO()
    pyhanko_sign_pdf(
        writer,
        PdfSignatureMetadata(field_name="Sig1"),
        signer,
        timestamper=timestamper,
        output=out_buf,
    )
    return out_buf.getvalue()


def sign_pdf(
    path: Path,
    config: SigningConfig,
    *,
    policy: SigningPolicy | None = None,
    material: SigningMaterial | None = None,
) -> PdfSignOutcome:
    """Sign a PDF in place with an embedded PAdES signature.

    Raises:
        SigningConfigError: the key material cannot be loaded.
        ReportSigningError: a TSA failure under ``REQUIRED``.
        Exception: pyHanko errors for a malformed PDF propagate; the caller applies
            the signing policy.
    """
    from pyhanko.sign.timestamps import HTTPTimeStamper
    from pyhanko.sign.timestamps.common_utils import TimestampRequestError

    effective = policy or config.policy
    material = material or config.load_material()
    signer = _pyhanko_signer(material)
    pdf_bytes = path.read_bytes()

    tsa_used = False
    if config.tsa_url is None:
        signed = _sign_bytes(pdf_bytes, signer, None)
    else:
        try:
            signed = _sign_bytes(pdf_bytes, signer, HTTPTimeStamper(config.tsa_url))
            tsa_used = True
        except (TimestampRequestError, OSError) as exc:  # OSError covers requests errors
            if effective is SigningPolicy.REQUIRED:
                raise ReportSigningError(
                    f"{path.name}: TSA request to {config.tsa_url} failed: {exc}"
                ) from exc
            logger.warning(
                "TSA request to %s failed while signing %s; downgrading to PAdES-B-B",
                config.tsa_url,
                path.name,
                exc_info=True,
            )
            signed = _sign_bytes(pdf_bytes, signer, None)

    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(signed)
    os.replace(tmp, path)
    return PdfSignOutcome(signer_fp=material.fingerprint, tsa=tsa_used)


def verify_pdf(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    """Verify every embedded PAdES signature on a PDF.

    Valid only when every signature is intact, cryptographically valid and trusted
    against the configured trust roots, and the last signature covers the whole
    file. Never fetches revocation data over the network.

    Returns (valid, error_message, metadata_dict).
    """
    try:
        return _do_verify_pdf(path, config)
    except SigningConfigError as exc:
        return False, str(exc), {}
    except Exception as exc:  # verification fails closed on any pyHanko/parse error
        return False, f"Verification error: {exc}", {}


def _do_verify_pdf(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.pdf_embedded import async_validate_pdf_signature
    from pyhanko.sign.validation.status import SignatureCoverageLevel

    trust_roots = config.load_trust_roots()

    with path.open("rb") as f:
        reader = PdfFileReader(f)
        sigs = reader.embedded_regular_signatures

        if not sigs:
            return False, "No embedded signatures found in PDF", {}

        reasons: list[str] = []
        meta: dict[str, object] = {}
        for index, sig in enumerate(sigs):
            vc = build_validation_context(trust_roots, config.crl_paths, config.revocation_mode)
            status = run_coroutine_sync(
                async_validate_pdf_signature(sig, signer_validation_context=vc)
            )
            label = f"signature {index + 1}" if len(sigs) > 1 else "signature"
            if not status.intact:
                reasons.append(f"{label}: document modified after signing")
            if not status.valid:
                reasons.append(f"{label}: signature cryptographically invalid")
            if not status.trusted:
                reasons.append(f"{label}: signer certificate not trusted")
            if not status.bottom_line:
                reasons.append(f"{label}: signature status not acceptable")
            if index == len(sigs) - 1:
                if status.coverage != SignatureCoverageLevel.ENTIRE_FILE:
                    reasons.append(f"{label}: content was appended after the last signature")
                meta = {
                    "intact": status.intact,
                    "valid": status.valid,
                    "trusted": status.trusted,
                    "has_timestamp": status.timestamp_validity is not None,
                    "cert_subject": str(status.signing_cert.subject.human_friendly),
                    "cert_fingerprint": f"sha256:{status.signing_cert.sha256.hex()}",
                }

    if reasons:
        # de-duplicate while keeping order
        return False, "; ".join(dict.fromkeys(reasons)), meta
    return True, None, meta
