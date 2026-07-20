"""Compatibility shims for Python 3.10 callers.

``datetime.UTC`` was added in Python 3.11. Import ``UTC`` from this module
instead of from ``datetime`` to keep the package working on Python 3.10
deployments.

Usage:

    from tarmo_vuln_core._compat import UTC
    now = datetime.datetime.now(UTC)
"""

from __future__ import annotations

try:
    from datetime import UTC  # 3.11+
except ImportError:  # pragma: no cover — 3.10 fallback
    from datetime import timezone

    UTC = timezone.utc  # noqa: UP017 — intentional 3.10 fallback

__all__ = ["UTC"]

try:
    from enum import StrEnum  # 3.11+
except ImportError:  # pragma: no cover — 3.10 fallback
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]  # noqa: UP042 — intentional 3.10 polyfill
        """Backport of 3.11s enum.StrEnum."""

        def __str__(self) -> str:
            return str(self.value)


__all__.append("StrEnum")
