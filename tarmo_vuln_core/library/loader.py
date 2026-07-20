"""Finding library loader — reads YAML files from finding_library/."""

from __future__ import annotations

from pathlib import Path

import yaml

# Default library directory shipped with the package (tarmo_vuln_core/finding_library/)
DEFAULT_LIBRARY_DIR = Path(__file__).parent.parent / "finding_library"


def load_library(*library_dirs: Path, scope_types: list[str] | None = None) -> dict[str, dict]:  # type: ignore[type-arg]
    """Load all finding definitions from one or more YAML directories.

    Each YAML file may contain a single finding mapping or a list of findings.
    Findings are keyed by their ``id`` field.  When the same ID appears in
    multiple directories, the last directory wins (custom dirs override the
    built-in library when placed after ``DEFAULT_LIBRARY_DIR``).

    Args:
        *library_dirs: One or more directories containing YAML finding
            definition files.  Non-existent paths are silently skipped.
        scope_types: Optional list of engagement type names (e.g. ``["web",
            "network"]``).  When non-empty, only YAML files whose stem
            (filename without ``.yaml``) matches one of the given names are
            loaded.  An empty list (the default) loads all files.

    Returns:
        Dict mapping finding id -> finding data dict.
    """
    library: dict[str, dict] = {}  # type: ignore[type-arg]
    _scope_set: frozenset[str] = frozenset(scope_types) if scope_types else frozenset()

    for library_dir in library_dirs:
        if not library_dir.exists():
            continue

        for yaml_file in sorted(library_dir.glob("*.yaml")):
            if _scope_set and yaml_file.stem not in _scope_set:
                continue

            with yaml_file.open() as f:
                data = yaml.safe_load(f)

            if data is None:
                continue

            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                if isinstance(entry, dict) and "id" in entry:
                    library[entry["id"]] = entry

    return library
