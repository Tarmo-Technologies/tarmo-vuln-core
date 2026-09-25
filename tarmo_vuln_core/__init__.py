"""tarmo-vuln-core: shared vulnerability processing library."""

from tarmo_vuln_core.dedup.merge import merge_findings, merge_instances
from tarmo_vuln_core.diff import ChangedFinding, DiffResult, diff_findings
from tarmo_vuln_core.ingestors import (
    REGISTRY,
    auto_detect,
    get_by_format,
    register_ingestor,
)
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import (
    DreadScore,
    Evidence,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingStatus,
    FuzzEvidence,
    Host,
    HostProperty,
    Instance,
    PortState,
    Protocol,
    ServiceName,
    Severity,
    StackFrame,
)
from tarmo_vuln_core.utils import get_xml_text, slugify
from tarmo_vuln_core.workflow import DEFAULT_TRANSITIONS, StatusWorkflow

__version__ = "0.2.0"

__all__ = [
    "BaseIngestor",
    "ChangedFinding",
    "merge_findings",
    "merge_instances",
    "DEFAULT_TRANSITIONS",
    "DiffResult",
    "DreadScore",
    "Evidence",
    "EvidenceType",
    "Finding",
    "FindingCategory",
    "FindingStatus",
    "FuzzEvidence",
    "Host",
    "HostProperty",
    "IngestorError",
    "Instance",
    "PortState",
    "Protocol",
    "REGISTRY",
    "Severity",
    "ServiceName",
    "StackFrame",
    "StatusWorkflow",
    "__version__",
    "auto_detect",
    "diff_findings",
    "get_by_format",
    "get_xml_text",
    "register_ingestor",
    "slugify",
]
