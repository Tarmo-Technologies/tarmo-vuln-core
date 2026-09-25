"""Base ingestor interface and shared exceptions."""

from __future__ import annotations

import functools
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from tarmo_vuln_core.models.finding import Finding, FindingCategory
from tarmo_vuln_core.models.host import Host


class IngestorError(Exception):
    """Raised when an ingestor cannot parse a file or the format is unrecognized."""


class UnsafeXmlError(IngestorError):
    """Raised when an XML report contains a forbidden construct.

    Entity declarations (internal or external) and external references are
    refused outright so entity-expansion ("billion laughs") and XXE payloads
    never get expanded or resolved.
    """


_IngestFn = Callable[..., list[Finding]]


def _with_default_category(ingest: _IngestFn) -> _IngestFn:
    """Wrap an ``ingest`` implementation so findings inherit the class category."""

    @functools.wraps(ingest)
    def wrapper(self: BaseIngestor, path: Path, *args: Any, **kwargs: Any) -> list[Finding]:
        findings = ingest(self, path, *args, **kwargs)
        category = self.category
        if category is not None:
            for finding in findings:
                if finding.category is None:
                    finding.category = category
        return findings

    wrapper.__fills_category__ = True  # type: ignore[attr-defined]
    return wrapper


class BaseIngestor(ABC):
    """Abstract base for all tool output ingestors.

    Ingestors are stateless: no instance state is shared between ingest() calls.

    Subclasses set :attr:`category` to classify the tool. Every finding returned
    by a subclass's ``ingest()`` whose ``category`` is still ``None`` is filled
    from it automatically — this applies however the ingestor is obtained
    (``auto_detect``, ``get_by_format``, direct instantiation or a plugin).
    """

    category: ClassVar[FindingCategory | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        ingest = cls.__dict__.get("ingest")
        if (
            ingest is not None
            and callable(ingest)
            and not getattr(ingest, "__isabstractmethod__", False)
            and not getattr(ingest, "__fills_category__", False)
        ):
            cls.ingest = _with_default_category(ingest)  # type: ignore[method-assign]

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
