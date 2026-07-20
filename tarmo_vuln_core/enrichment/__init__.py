"""CVE / NVD and LLM enrichment utilities."""

from tarmo_vuln_core.enrichment.llm import (
    LLMConfig,
    enrich_finding_from_llm,
    enrich_findings_from_llm,
)
from tarmo_vuln_core.enrichment.nvd import enrich_finding_from_nvd, enrich_findings_from_nvd

__all__ = [
    "LLMConfig",
    "enrich_finding_from_llm",
    "enrich_finding_from_nvd",
    "enrich_findings_from_llm",
    "enrich_findings_from_nvd",
]
