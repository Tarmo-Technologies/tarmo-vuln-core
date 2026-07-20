"""PAdES-T PDF signing and verification via pyhanko."""

from __future__ import annotations

import io
import logging
from pathlib import Path

from tarmo_vuln_core.signing.config import SigningConfig

logger = logging.getLogger(__name__)


def sign_pdf(path: Path, config: SigningConfig) -> None:
    """Sign a PDF file in-place using PAdES-B-T (with RFC 3161 timestamp).

    Falls back to PAdES-B (no timestamp) if the TSA is unreachable.
    Never raises — logs and returns on error.
    """
    try:
        _do_sign_pdf(path, config)
    except Exception:
        logger.warning("Failed to sign PDF %s", path, exc_info=True)


def _do_sign_pdf(path: Path, config: SigningConfig) -> None:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner
    from pyhanko.sign.signers import sign_pdf as pyhanko_sign_pdf
    from pyhanko.sign.timestamps import HTTPTimeStamper

    key_path = config.resolved_key_path()
    cert_path = config.resolved_cert_path()

    signer = SimpleSigner.load(str(key_path), str(cert_path))

    # Try RFC 3161 timestamp
    timestamper: HTTPTimeStamper | None = None
    try:
        timestamper = HTTPTimeStamper(config.tsa_url)
        # Probe connectivity with a small test — pyhanko will use it during sign_pdf
    except Exception:
        logger.warning("Could not initialise TSA at %s — signing without timestamp", config.tsa_url)
        timestamper = None

    sig_meta = PdfSignatureMetadata(field_name="Sig1")

    with open(path, "rb") as f:
        writer = IncrementalPdfFileWriter(f)
        out_buf = io.BytesIO()
        try:
            pyhanko_sign_pdf(
                writer,
                sig_meta,
                signer,
                timestamper=timestamper,
                output=out_buf,
            )
        except Exception:
            if timestamper is None:
                raise
            # TSA failed during signing — retry without timestamp
            logger.warning("TSA request failed during PDF signing — falling back to PAdES-B")
            with open(path, "rb") as f2:
                writer2 = IncrementalPdfFileWriter(f2)
                out_buf = io.BytesIO()
                pyhanko_sign_pdf(writer2, sig_meta, signer, timestamper=None, output=out_buf)

    path.write_bytes(out_buf.getvalue())


def verify_pdf(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    """Verify a PAdES signature on a PDF.

    Returns (valid, error_message, metadata_dict).
    """
    try:
        return _do_verify_pdf(path, config)
    except Exception as exc:
        return False, f"Verification error: {exc}", {}


def _do_verify_pdf(path: Path, config: SigningConfig) -> tuple[bool, str | None, dict[str, object]]:
    from asn1crypto import x509 as asn1_x509
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    cert_path = config.resolved_cert_path()
    cert_der = cert_path.read_bytes()
    # cert.pem -> load as DER via asn1crypto (works with DER; pem needs stripping)
    # Use the .der file if available, else convert pem
    cert_der_path = cert_path.parent / "signing.cert.der"
    if cert_der_path.exists():
        asn1_cert = asn1_x509.Certificate.load(cert_der_path.read_bytes())
    else:
        # Strip PEM headers
        from cryptography import x509 as cryptography_x509
        from cryptography.hazmat.primitives import serialization

        crypt_cert = cryptography_x509.load_pem_x509_certificate(cert_der)
        asn1_cert = asn1_x509.Certificate.load(crypt_cert.public_bytes(serialization.Encoding.DER))

    vc = ValidationContext(trust_roots=[asn1_cert], allow_fetching=False)

    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        sigs = reader.embedded_regular_signatures

        if not sigs:
            return False, "No embedded signatures found in PDF", {}

        # Validate the first signature
        status = validate_pdf_signature(sigs[0], signer_validation_context=vc)

        has_timestamp = status.timestamp_validity is not None

        meta: dict[str, object] = {
            "intact": status.intact,
            "valid": status.valid,
            "trusted": status.trusted,
            "has_timestamp": has_timestamp,
            "cert_subject": str(status.signing_cert.subject.human_friendly),
            "cert_fingerprint": f"sha256:{status.signing_cert.sha256_fingerprint}",
        }

        if status.intact and status.valid:
            return True, None, meta

        reasons = []
        if not status.intact:
            reasons.append("document modified after signing")
        if not status.valid:
            reasons.append("signature cryptographically invalid")
        if not status.trusted:
            reasons.append("signer certificate not trusted")

        return False, "; ".join(reasons) or "signature invalid", meta
