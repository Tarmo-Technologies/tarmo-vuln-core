"""Base ingestor interface and shared exceptions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from tarmo_vuln_core.models.finding import Finding
from tarmo_vuln_core.models.host import Host


class IngestorError(Exception):
    """Raised when an ingestor cannot parse a file or the format is unrecognized."""


class BaseIngestor(ABC):
    """Abstract base for all tool output ingestors.

    Ingestors are stateless: no instance state is shared between ingest() calls.
    """

    @abstractmethod
    def can_handle(self, path: Path) -> bool:
        """Return True if this ingestor can parse the given file."""
        ...

    @abstractmethod
    def ingest(self, path: Path) -> list[Finding]:
        """Parse the file and return a list of normalized Finding objects.

        Raises:
            IngestorError: If the file cannot be parsed.
        """
        ...

    @property
    def supported_extensions(self) -> list[str]:
        """Return file extensions this ingestor handles (e.g. ``[".xml"]``)."""
        return []

    def extract_scanner_version(self, raw: bytes) -> str | None:
        """Return the scanner's reported version from the raw report, or None
        if the tool does not surface one in its output."""
        return None

    def ingest_hosts(self, path: Path) -> list[Host]:
        """Parse the file and return per-host metadata records.

        The default returns an empty list.
        """
        return []
