"""Discovery and loading of custom ingestor plugins.

Custom plugins are Python files placed in:
  - .tarmo-vuln-core/ingestors/  (project-local, loaded first)
  - ~/.config/tarmo-vuln-core/ingestors/  (user-global)

Each file must define at least one class that subclasses BaseIngestor.

WARNING: Custom plugins execute arbitrary Python code with full user privileges.
Only load plugin files you trust.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor

logger = logging.getLogger(__name__)

_USER_PLUGIN_DIR: Path = Path.home() / ".config" / "tarmo-vuln-core" / "ingestors"


def _load_plugin_file(path: Path) -> list[BaseIngestor]:
    """Load a single .py file and return instances of any BaseIngestor subclasses found.

    Args:
        path: Absolute path to the Python plugin file.

    Returns:
        List of instantiated BaseIngestor subclasses discovered in the file.
        Empty list if the file fails to import or contains no ingestor classes.
    """
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        logger.warning("Could not create module spec for plugin: %s", path)
        return []

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        logger.warning("Failed to load plugin %s: %s", path.name, exc)
        return []

    instances: list[BaseIngestor] = []
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(obj, BaseIngestor)
            and obj is not BaseIngestor
            and obj.__module__ == module.__name__
        ):
            try:
                instances.append(obj())
            except Exception as exc:
                logger.warning(
                    "Could not instantiate plugin class %s in %s: %s", name, path.name, exc
                )

    return instances


def load_plugins(project_dir: Path | None = None) -> list[tuple[BaseIngestor, str]]:
    """Load custom ingestors from plugin directories.

    Scans two locations in priority order:
    1. ``<project_dir>/.tarmo-vuln-core/ingestors/`` (project-local, higher priority)
    2. ``~/.config/tarmo-vuln-core/ingestors/`` (user-global)

    Args:
        project_dir: Root of the project directory. Defaults to CWD.

    Returns:
        List of ``(ingestor_instance, source)`` tuples where ``source`` is
        ``"project"`` or ``"user"``.
    """
    root = project_dir or Path()
    project_plugin_dir = root / ".tarmo-vuln-core" / "ingestors"

    results: list[tuple[BaseIngestor, str]] = []
    for dir_path, source in [(project_plugin_dir, "project"), (_USER_PLUGIN_DIR, "user")]:
        if not dir_path.is_dir():
            continue
        for plugin_file in sorted(dir_path.glob("*.py")):
            logger.warning(
                "Loading custom ingestor plugin: %s — "
                "custom plugins run with full user privileges.",
                plugin_file,
            )
            for ingestor in _load_plugin_file(plugin_file):
                results.append((ingestor, source))

    return results
