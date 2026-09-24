"""Built-in parser registry for tarmo-vuln-core.

Exports ``register_all()`` which populates a registry list with all 40 parsers
in the canonical specificity order.
"""

from __future__ import annotations

from tarmo_vuln_core.ingestors.base import BaseIngestor
from tarmo_vuln_core.ingestors.parsers.acunetix import AcunetixIngestor
from tarmo_vuln_core.ingestors.parsers.bandit import BanditIngestor
from tarmo_vuln_core.ingestors.parsers.bhf import BhfIngestor, BhfStaticIngestor
from tarmo_vuln_core.ingestors.parsers.binary_analyzer import BinwalkIngestor, StringsIngestor
from tarmo_vuln_core.ingestors.parsers.bloodhound import BloodHoundIngestor
from tarmo_vuln_core.ingestors.parsers.burp import BurpIngestor
from tarmo_vuln_core.ingestors.parsers.checkmarx import CheckmarxIngestor
from tarmo_vuln_core.ingestors.parsers.config_analyzer import ConfigAnalyzerIngestor
from tarmo_vuln_core.ingestors.parsers.coverity import CoverityIngestor
from tarmo_vuln_core.ingestors.parsers.cppcheck import CppcheckIngestor
from tarmo_vuln_core.ingestors.parsers.csv_finding import CsvFindingIngestor
from tarmo_vuln_core.ingestors.parsers.eslint import EslintIngestor
from tarmo_vuln_core.ingestors.parsers.fortify import FortifyIngestor
from tarmo_vuln_core.ingestors.parsers.gitleaks import GitleaksIngestor
from tarmo_vuln_core.ingestors.parsers.gnatsas import GnatSasIngestor
from tarmo_vuln_core.ingestors.parsers.hackerone import HackerOneIngestor
from tarmo_vuln_core.ingestors.parsers.manual import ManualIngestor
from tarmo_vuln_core.ingestors.parsers.metasploit import MetasploitIngestor
from tarmo_vuln_core.ingestors.parsers.nessus import NessusIngestor
from tarmo_vuln_core.ingestors.parsers.nexpose import NexposeIngestor
from tarmo_vuln_core.ingestors.parsers.nikto import NiktoIngestor
from tarmo_vuln_core.ingestors.parsers.nmap import NmapIngestor
from tarmo_vuln_core.ingestors.parsers.openvas import OpenvasIngestor
from tarmo_vuln_core.ingestors.parsers.owasp_depcheck import OwaspDepcheckIngestor
from tarmo_vuln_core.ingestors.parsers.pragmatic import PragmaticIngestor
from tarmo_vuln_core.ingestors.parsers.pylint_ingestor import PylintIngestor
from tarmo_vuln_core.ingestors.parsers.qualys import QualysIngestor
from tarmo_vuln_core.ingestors.parsers.sarif import SarifIngestor
from tarmo_vuln_core.ingestors.parsers.sarp import SarpIngestor, SarpSchemaError
from tarmo_vuln_core.ingestors.parsers.semgrep import SemgrepIngestor
from tarmo_vuln_core.ingestors.parsers.sigasi import SigasiIngestor
from tarmo_vuln_core.ingestors.parsers.srm import SrmIngestor
from tarmo_vuln_core.ingestors.parsers.sslyze import SslyzeIngestor
from tarmo_vuln_core.ingestors.parsers.tenable import TenableIngestor
from tarmo_vuln_core.ingestors.parsers.trivy import TrivyIngestor
from tarmo_vuln_core.ingestors.parsers.trufflehog import TrufflehogIngestor
from tarmo_vuln_core.ingestors.parsers.wpscan import WpscanIngestor
from tarmo_vuln_core.ingestors.parsers.zap import ZapIngestor

# Ordered: more-specific formats first to avoid false positives.
# Key ordering constraints:
#   - GnatSasIngestor before SarifIngestor (SARIF subclass with stricter can_handle)
#   - SarpIngestor and PragmaticIngestor before CsvFindingIngestor (more specific CSV)
#   - FortifyIngestor and CheckmarxIngestor early (highly specific file formats)
#   - BhfIngestor before every CSV/JSON catch-all (Pragmatic, Sarp, CsvFinding,
#     Manual): it sniffs the exact BHF findings.csv header / finding.json keys
#     and is the only ingestor that accepts a directory (a BHF work dir)
#   - BhfStaticIngestor before SemgrepIngestor/GnatSasIngestor/SarifIngestor so
#     BHF's static-report.sarif is not swallowed by the generic SARIF parser
# ManualIngestor is last — it accepts any YAML/JSON.
DEFAULT_REGISTRY_ORDER: list[type[BaseIngestor]] = [
    NessusIngestor,
    NexposeIngestor,
    NmapIngestor,
    BurpIngestor,
    AcunetixIngestor,
    NiktoIngestor,
    ZapIngestor,
    OpenvasIngestor,
    QualysIngestor,
    MetasploitIngestor,
    TrivyIngestor,
    WpscanIngestor,
    SslyzeIngestor,
    TenableIngestor,
    BhfIngestor,
    BhfStaticIngestor,
    FortifyIngestor,
    CheckmarxIngestor,
    SrmIngestor,
    CoverityIngestor,
    OwaspDepcheckIngestor,
    EslintIngestor,
    PylintIngestor,
    SigasiIngestor,
    SemgrepIngestor,
    GnatSasIngestor,
    SarifIngestor,
    BloodHoundIngestor,
    HackerOneIngestor,
    BanditIngestor,
    CppcheckIngestor,
    GitleaksIngestor,
    TrufflehogIngestor,
    StringsIngestor,
    BinwalkIngestor,
    ConfigAnalyzerIngestor,
    PragmaticIngestor,
    SarpIngestor,
    CsvFindingIngestor,
    ManualIngestor,
]

__all__ = [
    "AcunetixIngestor",
    "BanditIngestor",
    "BhfIngestor",
    "BhfStaticIngestor",
    "BinwalkIngestor",
    "BloodHoundIngestor",
    "BurpIngestor",
    "CheckmarxIngestor",
    "ConfigAnalyzerIngestor",
    "CoverityIngestor",
    "CppcheckIngestor",
    "CsvFindingIngestor",
    "DEFAULT_REGISTRY_ORDER",
    "EslintIngestor",
    "FortifyIngestor",
    "GitleaksIngestor",
    "GnatSasIngestor",
    "HackerOneIngestor",
    "ManualIngestor",
    "MetasploitIngestor",
    "NessusIngestor",
    "NexposeIngestor",
    "NiktoIngestor",
    "NmapIngestor",
    "OpenvasIngestor",
    "OwaspDepcheckIngestor",
    "PragmaticIngestor",
    "PylintIngestor",
    "QualysIngestor",
    "SarifIngestor",
    "SarpIngestor",
    "SarpSchemaError",
    "SemgrepIngestor",
    "SigasiIngestor",
    "SrmIngestor",
    "SslyzeIngestor",
    "StringsIngestor",
    "TenableIngestor",
    "TrivyIngestor",
    "TrufflehogIngestor",
    "WpscanIngestor",
    "ZapIngestor",
    "register_all",
]


def register_all(registry: list[BaseIngestor]) -> None:
    """Instantiate and append all 40 built-in parsers to *registry*."""
    for cls in DEFAULT_REGISTRY_ORDER:
        registry.append(cls())
