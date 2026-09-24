"""Finding model, severity, status, evidence, and instance types."""

from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from tarmo_vuln_core._compat import StrEnum


class Severity(StrEnum):
    """Finding severity levels with ordinal comparison support."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def _ordinal(self) -> int:
        return _SEVERITY_ORDER[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._ordinal() < other._ordinal()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._ordinal() <= other._ordinal()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._ordinal() > other._ordinal()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._ordinal() >= other._ordinal()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


# Higher number = higher severity
_SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class FindingStatus(StrEnum):
    """Lifecycle status for a finding, tracking remediation progress."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    PROVISIONAL = "provisional"
    POTENTIAL = "potential"


_EVIDENCE_TYPE_BY_EXT: dict[str, EvidenceType] = {}  # populated after EvidenceType is defined


class FindingCategory(StrEnum):
    """Broad class of tool / technique that produced a finding.

    Set per-ingestor via ``BaseIngestor.category`` and filled onto every
    finding the ingestor returns unless the ingestor set one explicitly.
    """

    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    SECRETS = "secrets"
    FUZZ = "fuzz"
    INFRASTRUCTURE = "infrastructure"
    BINARY = "binary"
    CONFIG = "config"
    MANUAL = "manual"
    OTHER = "other"


class EvidenceType(StrEnum):
    """Type classification for a piece of evidence."""

    SCREENSHOT = "screenshot"
    LOG = "log"
    PCAP = "pcap"
    HTTP = "http"
    DOCUMENT = "document"
    OTHER = "other"


_EVIDENCE_TYPE_BY_EXT = {
    ".png": EvidenceType.SCREENSHOT,
    ".jpg": EvidenceType.SCREENSHOT,
    ".jpeg": EvidenceType.SCREENSHOT,
    ".gif": EvidenceType.SCREENSHOT,
    ".webp": EvidenceType.SCREENSHOT,
    ".bmp": EvidenceType.SCREENSHOT,
    ".log": EvidenceType.LOG,
    ".txt": EvidenceType.LOG,
    ".pcap": EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
    ".har": EvidenceType.HTTP,
    ".pdf": EvidenceType.DOCUMENT,
    ".docx": EvidenceType.DOCUMENT,
    ".doc": EvidenceType.DOCUMENT,
}


def _infer_evidence_type(filename: str) -> EvidenceType:
    """Infer EvidenceType from file extension, falling back to OTHER."""
    ext = Path(filename).suffix.lower()
    return _EVIDENCE_TYPE_BY_EXT.get(ext, EvidenceType.OTHER)


class Evidence(BaseModel):
    """A piece of evidence associated with a finding."""

    model_config = ConfigDict(str_strip_whitespace=True)

    filename: str
    path: Path | None = None
    caption: str = ""
    type: EvidenceType = EvidenceType.OTHER
    request: str = ""
    response: str = ""

    @model_validator(mode="before")
    @classmethod
    def infer_type_from_filename(cls, values: Any) -> Any:
        """Auto-infer evidence type from filename extension if not explicitly provided."""
        if isinstance(values, dict) and "type" not in values:
            filename = values.get("filename", "")
            if filename:
                values = dict(values)
                values["type"] = _infer_evidence_type(str(filename))
        return values


class SourceCodeRef(BaseModel):
    """Reference to a specific source code location."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    column: int | None = None
    symbol: str | None = None
    is_sink: bool = True
    snippet: str = ""
    repository: str = ""
    branch: str = ""
    commit_sha: str = ""


class StackFrame(BaseModel):
    """One frame of a crash stack. ``file`` is relative to the scanned source root."""

    file: str | None = None
    function: str | None = None
    line: int | None = None


class FuzzEvidence(BaseModel):
    """Fuzzer-specific evidence attached to a dynamically confirmed finding.

    ``stack`` holds project frames only (fuzzer runtime, harness, libc and
    sanitizer frames are dropped by the ingestor). Paths are POSIX-relative to
    the scanned source root; ``reproducer_path`` is relative to the fuzzer's
    work directory.
    """

    engine: str
    finding_id: str
    rule_id: str | None = None
    exception_name: str | None = None
    sanitizer: str | None = None
    classification: str | None = None
    verdict: str | None = None
    confidence: str | None = None
    confirmation: str | None = None
    harness_id: str | None = None
    cluster_key: str | None = None
    signature: str | None = None
    member_ids: list[str] = []
    stack: list[StackFrame] = []
    reproducer_path: str | None = None
    replay_command: str | None = None
    prosthetics_used: bool | None = None
    cwe_ids: list[int] = []


class RuntimeTarget(BaseModel):
    """A runtime test target derived from code analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = ""
    method: str = ""
    parameter: str = ""
    host: str = ""
    port: int | None = None
    protocol: str = ""
    test_payloads: list[str] = []
    confidence: str = "low"
    notes: str = ""


class DreadScore(BaseModel):
    """DREAD risk scoring model — five dimensions scored 0-10.

    Risk = (Damage + Reproducibility + Exploitability + Affected_users + Discoverability) / 5
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int

    @field_validator(
        "damage", "reproducibility", "exploitability", "affected_users", "discoverability"
    )
    @classmethod
    def validate_range(cls, v: int) -> int:
        if not (0 <= v <= 10):
            raise ValueError(f"DREAD dimension must be 0-10, got {v}")
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> float:
        return (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        ) / 5

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> Severity:
        t = self.total
        if t >= 8:
            return Severity.CRITICAL
        if t >= 6:
            return Severity.HIGH
        if t >= 4:
            return Severity.MEDIUM
        return Severity.LOW


class Instance(BaseModel):
    """A specific occurrence of a vulnerability on a particular host/port/path."""

    model_config = ConfigDict(str_strip_whitespace=True)

    host: str
    port: int | None = None
    path: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    notes: str = ""
    evidence: list[Evidence] = []
    verified_at: datetime | None = None


class Finding(BaseModel):
    """A normalized security finding, populated by ingestors or entered manually."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cvss_v4_score: float | None = None
    cvss_v4_vector: str | None = None
    cwe_id: int | None = None
    owasp_id: str | None = None
    category: FindingCategory | None = None
    affected_hosts: list[str] = []
    source_code_refs: list[SourceCodeRef] = []
    runtime_targets: list[RuntimeTarget] = []
    fuzz: FuzzEvidence | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: list[Evidence] = []
    instances: list[Instance] = []
    source_tool: str = "manual"
    source_tools: list[str] = []
    raw_ref: str | None = None
    steps: list[str] = []
    compliance_refs: list[str] = []
    owasp_likelihood: int | None = None
    owasp_impact: int | None = None
    status: FindingStatus = FindingStatus.OPEN
    remediated_at: datetime | None = None
    verified_at: datetime | None = None
    notes: str = ""
    published: bool = True
    tags: list[str] = []
    attack_ids: list[str] = []
    attack_tactics: list[str] = []
    dread_score: DreadScore | None = None
    finding_guidance: str = ""
    mitigation: str = ""
    replication_steps: str = ""
    host_detection_techniques: str = ""
    network_detection_techniques: str = ""
    extra_fields: dict[str, Any] = {}
    methodology_items: list[str] = []  # WSTG item IDs auto-marked on ingest (e.g. ["INPV-01"])
    false_positive: bool = False
    starred: bool = False
    remediation_due: date | None = None
    sla_days: int | None = None
    provisional_until: date | None = None

    @field_validator("cvss_score", "cvss_v4_score")
    @classmethod
    def validate_cvss_range(cls, v: float | None) -> float | None:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError(f"CVSS score must be between 0.0 and 10.0, got {v}")
        return v

    @field_validator("owasp_likelihood", "owasp_impact")
    @classmethod
    def validate_owasp_range(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 9):
            raise ValueError(f"OWASP likelihood/impact must be 1-9, got {v}")
        return v

    @model_validator(mode="after")
    def _retracted_findings_unpublished(self) -> Finding:
        """A FALSE_POSITIVE finding (or one with the legacy bool set) is a retracted
        claim and must never be published, regardless of how it was constructed.

        This is a structural invariant: any consumer reading published findings
        from any code path is guaranteed not to see retracted ones (#204).
        """
        if self.status == FindingStatus.FALSE_POSITIVE or self.false_positive:
            self.published = False
        return self

    @model_validator(mode="after")
    def _sync_source_tools(self) -> Finding:
        """Keep ``source_tool`` and ``source_tools`` in sync (#45)."""
        if self.source_tools and self.source_tool == "manual":
            self.source_tool = self.source_tools[0]
        elif self.source_tool != "manual" and not self.source_tools:
            self.source_tools = [self.source_tool]
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_overdue(self) -> bool:
        """True if the remediation_due date is in the past and the finding is still active."""
        if self.remediation_due is None:
            return False
        _closed = {
            FindingStatus.RESOLVED,
            FindingStatus.VERIFIED,
            FindingStatus.MITIGATED,
            FindingStatus.RISK_ACCEPTED,
        }
        if self.status in _closed:
            return False
        return self.remediation_due < date.today()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_provisional_expired(self) -> bool:
        """True if status is PROVISIONAL and the provisional_until date has passed."""
        if self.status != FindingStatus.PROVISIONAL:
            return False
        if self.provisional_until is None:
            return False
        return self.provisional_until < date.today()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def owasp_risk_score(self) -> float | None:
        if self.owasp_likelihood is not None and self.owasp_impact is not None:
            return round(self.owasp_likelihood * self.owasp_impact / 9, 1)
        return None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def owasp_risk_rating(self) -> str | None:
        score = self.owasp_risk_score
        if score is None:
            return None
        if score >= 7.5:
            return "CRITICAL"
        if score >= 5.0:
            return "HIGH"
        if score >= 2.5:
            return "MEDIUM"
        return "LOW"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def content_hash(self) -> str:
        """SHA-256 hash for deterministic deduplication.

        Based on id, title, severity, sorted affected_hosts, and description.
        """
        parts = "|".join(
            [
                self.id,
                self.title,
                self.severity.value,
                ",".join(sorted(self.affected_hosts)),
                self.description,
            ]
        )
        return hashlib.sha256(parts.encode()).hexdigest()
