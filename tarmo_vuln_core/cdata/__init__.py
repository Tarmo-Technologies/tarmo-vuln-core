"""CData mapping registry for CWE/confidence lookup by tool and query."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CDataMatch:
    """Result of a CData lookup."""

    cwe: int
    confidence: str | None = None
    severity: str | None = None


_MAPPINGS_DIR = Path(__file__).parent / "mappings"


def discover_tool_files(mappings_dir: Path = _MAPPINGS_DIR) -> dict[str, Path]:
    """Discover built-in tool mapping files in the mappings directory."""
    return {
        path.stem: path
        for path in sorted(mappings_dir.glob("*.json"))
        if path.name != "mitre_cwe_categories.json"
    }


class CDataRegistry:
    """Central registry for CWE/confidence mappings per tool.

    Each tool's mapping is a flat ``query → {cwe, confidence?, severity?}`` dict.
    Lookup is O(1) via nested dict access.
    """

    def __init__(self, mappings_dir: Path = _MAPPINGS_DIR) -> None:
        self._mappings_dir = mappings_dir
        self._mappings: dict[str, dict[str, dict[str, Any]]] = {}
        self._mitre: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        """Load all built-in JSON mapping files."""
        for tool, path in discover_tool_files(self._mappings_dir).items():
            self._mappings[tool] = json.loads(path.read_text("utf-8"))

        mitre_path = self._mappings_dir / "mitre_cwe_categories.json"
        if mitre_path.exists():
            self._mitre = json.loads(mitre_path.read_text("utf-8"))

    def lookup(
        self,
        tool: str,
        query: str,
        *,
        overrides: list[dict[str, Any]] | None = None,
    ) -> CDataMatch | None:
        """Look up CWE/confidence for a tool query.

        Priority: user overrides → built-in defaults → None.
        """
        # Check user overrides first
        if overrides:
            for ovr in overrides:
                if ovr.get("tool") == tool and ovr.get("query") == query:
                    cwe = ovr.get("cwe")
                    if cwe is not None:
                        return CDataMatch(
                            cwe=int(cwe),
                            confidence=ovr.get("confidence"),
                            severity=ovr.get("severity"),
                        )

        # Check built-in mappings
        tool_map = self._mappings.get(tool)
        if tool_map is None:
            return None

        entry = tool_map.get(query)
        if entry is None:
            return None

        cwe = entry.get("cwe")
        if cwe is None:
            return None

        return CDataMatch(
            cwe=int(cwe),
            confidence=entry.get("confidence"),
            severity=entry.get("severity"),
        )

    def mitre_category(self, cwe_id: int) -> str | None:
        """Look up the MITRE category for a CWE ID."""
        return self._mitre.get(str(cwe_id))


# Module-level singleton
_default_registry: CDataRegistry | None = None


def default_registry() -> CDataRegistry:
    """Return the shared default CDataRegistry instance."""
    global _default_registry
    if _default_registry is None:
        _default_registry = CDataRegistry()
    return _default_registry
