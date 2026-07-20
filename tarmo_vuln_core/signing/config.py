"""SigningConfig — Pydantic v2 model with env var resolution."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel

_DEFAULT_SIGNING_DIR = Path.home() / ".config" / "tarmo" / "signing"


class SigningConfig(BaseModel):
    enabled: bool = True
    key_path: Path | None = None
    cert_path: Path | None = None
    tsa_url: str = "https://freetsa.org/tsr"

    @classmethod
    def from_env(cls) -> SigningConfig:
        """Resolve config from environment variables."""
        enabled_raw = os.environ.get("TARMO_SIGNING_ENABLED", "true").lower()
        enabled = enabled_raw not in ("false", "0", "no")

        key_raw = os.environ.get("TARMO_SIGNING_KEY")
        cert_raw = os.environ.get("TARMO_SIGNING_CERT")
        tsa_url = os.environ.get("TARMO_SIGNING_TSA_URL", "https://freetsa.org/tsr")

        return cls(
            enabled=enabled,
            key_path=Path(key_raw) if key_raw else None,
            cert_path=Path(cert_raw) if cert_raw else None,
            tsa_url=tsa_url,
        )

    def resolved_key_path(self) -> Path:
        return self.key_path or (_DEFAULT_SIGNING_DIR / "signing.key.pem")

    def resolved_cert_path(self) -> Path:
        return self.cert_path or (_DEFAULT_SIGNING_DIR / "signing.cert.pem")

    def resolved_signing_dir(self) -> Path:
        return self.resolved_key_path().parent
