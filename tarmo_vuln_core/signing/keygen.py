"""Auto-generate ECDSA P-256 keypair and self-signed X.509 cert."""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tarmo_vuln_core._compat import UTC

logger = logging.getLogger(__name__)


def ensure_keys_exist(signing_dir: Path) -> None:
    """Generate ECDSA P-256 keypair + self-signed cert if they don't exist.

    Idempotent — skips generation if all three files already exist.
    """
    key_path = signing_dir / "signing.key.pem"
    cert_pem_path = signing_dir / "signing.cert.pem"
    cert_der_path = signing_dir / "signing.cert.der"

    if key_path.exists() and cert_pem_path.exists() and cert_der_path.exists():
        return

    signing_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Generating signing keypair in %s", signing_dir)

    private_key = ec.generate_private_key(ec.SECP256R1())

    # Build cert subject from env vars
    cn = os.environ.get("TARMO_SIGNER_CN", "Tarmo Report Signer")
    org = os.environ.get("TARMO_SIGNER_ORG", "")
    email = os.environ.get("TARMO_SIGNER_EMAIL", "")

    name_attrs = [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)]
    if org:
        name_attrs.append(x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, org))

    subject = x509.Name(name_attrs)
    now = datetime.datetime.now(UTC)

    san_list: list[x509.GeneralName] = []
    if email:
        san_list.append(x509.RFC822Name(email))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(private_key, hashes.SHA256())

    # Write private key — mode 0600
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    os.chmod(key_path, 0o600)

    # Write cert PEM
    cert_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Write cert DER
    cert_der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    logger.info("Signing keys generated: CN=%s", cn)
