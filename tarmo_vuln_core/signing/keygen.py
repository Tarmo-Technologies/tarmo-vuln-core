"""Generate a development ECDSA P-256 keypair and self-signed X.509 certificate.

Used only for the ``dev_selfsigned`` key source. Files are created with
``O_CREAT | O_EXCL`` so a pre-planted file or symlink is never followed or
overwritten, and the private key is created mode 0600 (no chmod race).
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tarmo_vuln_core._compat import UTC
from tarmo_vuln_core.signing.config import SigningConfigError

logger = logging.getLogger(__name__)

KEY_FILE = "signing.key.pem"
CERT_PEM_FILE = "signing.cert.pem"
CERT_DER_FILE = "signing.cert.der"

# Files that mark a directory as holding operator-provisioned key material.
_OPERATOR_MARKERS = ("local-ca.json", "local-ca.key.pem", "signing.crt.pem")
_OPERATOR_GLOBS = ("*.p12", "*.pfx")


def write_new_file(path: Path, data: bytes, mode: int) -> None:
    """Create ``path`` exclusively with ``mode`` and write ``data``.

    Raises:
        SigningConfigError: the path already exists (including as a symlink).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise SigningConfigError(f"refusing to overwrite existing file {path}") from exc
    except OSError as exc:
        raise SigningConfigError(f"cannot create {path}: {exc}") from exc
    try:
        os.fchmod(fd, mode)  # exact mode regardless of the process umask
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
    finally:
        if fd != -1:
            os.close(fd)


def _check_not_operator_dir(signing_dir: Path) -> None:
    for name in _OPERATOR_MARKERS:
        if (signing_dir / name).exists():
            raise SigningConfigError(
                f"{signing_dir} holds operator key material ({name}); "
                "refusing to generate a dev_selfsigned key there"
            )
    for pattern in _OPERATOR_GLOBS:
        for match in signing_dir.glob(pattern):
            raise SigningConfigError(
                f"{signing_dir} holds operator key material ({match.name}); "
                "refusing to generate a dev_selfsigned key there"
            )


def ensure_keys_exist(signing_dir: Path) -> None:
    """Generate an ECDSA P-256 keypair + self-signed cert if none exist.

    Idempotent: returns without change when all three files already exist.

    Raises:
        SigningConfigError: only some of the files exist, the directory holds
            operator key material, or a file cannot be created exclusively.
    """
    key_path = signing_dir / KEY_FILE
    cert_pem_path = signing_dir / CERT_PEM_FILE
    cert_der_path = signing_dir / CERT_DER_FILE
    targets = (key_path, cert_pem_path, cert_der_path)

    present = [p for p in targets if p.is_symlink() or p.exists()]
    if len(present) == len(targets) and not any(p.is_symlink() for p in targets):
        return
    if present:
        missing = [p.name for p in targets if p not in present]
        linked = [p.name for p in targets if p.is_symlink()]
        detail = f"symlinked: {', '.join(linked)}" if linked else f"missing: {', '.join(missing)}"
        raise SigningConfigError(
            f"partial dev signing key material in {signing_dir} ({detail}); "
            "remove the directory contents to regenerate"
        )

    if signing_dir.exists():
        _check_not_operator_dir(signing_dir)
    else:
        signing_dir.mkdir(parents=True, mode=0o700)
        os.chmod(signing_dir, 0o700)  # mkdir mode is filtered by umask

    logger.info("Generating dev_selfsigned signing keypair in %s", signing_dir)

    private_key = ec.generate_private_key(ec.SECP256R1())

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

    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    write_new_file(key_path, key_pem, 0o600)
    write_new_file(cert_pem_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    write_new_file(cert_der_path, cert.public_bytes(serialization.Encoding.DER), 0o644)

    logger.info("Signing keys generated: CN=%s", cn)
