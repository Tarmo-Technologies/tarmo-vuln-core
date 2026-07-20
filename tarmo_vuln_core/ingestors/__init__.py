"""Ingestor registry and auto-detection for tarmo-vuln-core."""

from __future__ import annotations

import re
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.ingestors.parsers import (
    AcunetixIngestor,
    BloodHoundIngestor,
    BurpIngestor,
    CsvFindingIngestor,
    HackerOneIngestor,
    ManualIngestor,
    MetasploitIngestor,
    NessusIngestor,
    NexposeIngestor,
    NiktoIngestor,
    NmapIngestor,
    OpenvasIngestor,
    QualysIngestor,
    SarifIngestor,
    SslyzeIngestor,
    TenableIngestor,
    TrivyIngestor,
    WpscanIngestor,
    ZapIngestor,
    register_all,
)

# Registry populated with all 38 built-in parsers at import time.
REGISTRY: list[BaseIngestor] = []
register_all(REGISTRY)

__all__ = [
    "AcunetixIngestor",
    "BaseIngestor",
    "BloodHoundIngestor",
    "BurpIngestor",
    "CsvFindingIngestor",
    "HackerOneIngestor",
    "IngestorError",
    "ManualIngestor",
    "MetasploitIngestor",
    "NessusIngestor",
    "NexposeIngestor",
    "NiktoIngestor",
    "NmapIngestor",
    "OpenvasIngestor",
    "QualysIngestor",
    "REGISTRY",
    "SarifIngestor",
    "SslyzeIngestor",
    "TenableIngestor",
    "TrivyIngestor",
    "WpscanIngestor",
    "ZapIngestor",
    "auto_detect",
    "get_by_format",
    "register_ingestor",
]


def register_ingestor(ingestor: BaseIngestor) -> None:
    """Register an ingestor instance in the global registry.

    Consumer packages (pentest-scribe and other downstream consumers) call
    this to register their concrete parsers or custom plugins.

    Args:
        ingestor: An instance of a BaseIngestor subclass.
    """
    REGISTRY.append(ingestor)


def get_by_format(name: str, extra: list[BaseIngestor] | None = None) -> BaseIngestor | None:
    """Return the ingestor matching the given format name, or None.

    Format names are derived from the class name by stripping the "Ingestor"
    suffix and lowercasing: ``NmapIngestor`` -> ``"nmap"``.

    Args:
        name: Format name string (case-insensitive).
        extra: Optional list of additional ingestor instances (e.g., plugins).

    Returns:
        Matching BaseIngestor instance, or None if not found.
    """
    name_lower = name.lower()
    all_ingestors: list[BaseIngestor] = REGISTRY + (extra or [])
    for ingestor in all_ingestors:
        base = ingestor.__class__.__name__.removesuffix("Ingestor")
        collapsed = base.lower()
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", base).lower()
        if name_lower in (collapsed, snake):
            return ingestor
    return None


def auto_detect(path: Path, extra: list[BaseIngestor] | None = None) -> BaseIngestor:
    """Return the first ingestor that claims it can handle the given file.

    Args:
        path: Path to the file to detect.
        extra: Optional list of additional ingestor instances to try after
            the built-in registry.

    Returns:
        The first matching BaseIngestor.

    Raises:
        IngestorError: If the file does not exist or no ingestor can handle it.
    """
    if not path.exists():
        raise IngestorError(f"File not found: {path}")

    all_ingestors: list[BaseIngestor] = REGISTRY + (extra or [])
    for ingestor in all_ingestors:
        if ingestor.can_handle(path):
            return ingestor

    raise IngestorError(
        f"No ingestor could handle '{path.name}'. "
        "Supported formats: nmap XML, .nessus, Nexpose XML, Burp XML, Acunetix XML, "
        "Nikto XML, ZAP XML, OpenVAS XML, Qualys XML, Metasploit CSV/XML, "
        "Trivy JSON, WPScan JSON, SSLyze JSON, Tenable.io JSON, SARIF 2.1.0 JSON, "
        "BloodHound JSON, HackerOne JSON, Coverity JSON, Fortify .fpr/.fvdl, "
        "CSV findings, YAML/JSON manual."
    )
