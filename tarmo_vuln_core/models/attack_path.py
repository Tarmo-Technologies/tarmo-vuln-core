"""Shared attack path, exploit metadata, and credential models.

Used by both pentest-storm (execution) and pentest-scribe (reporting).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from tarmo_vuln_core.models.finding import Evidence


class AttackStep(BaseModel):
    """One step in an attack path — maps to MITRE ATT&CK techniques."""

    model_config = ConfigDict(str_strip_whitespace=True)

    source_host: str
    target_host: str
    technique: str  # ATT&CK technique ID (e.g., T1021.002)
    tactic: str  # ATT&CK tactic (e.g., "Lateral Movement")
    tool_used: str
    credential_used: str = ""
    evidence: list[Evidence] = []
    timestamp: datetime | None = None
    notes: str = ""
    success: bool = True


class AttackPath(BaseModel):
    """A multi-step attack path from initial access to objective."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    name: str
    steps: list[AttackStep] = []
    objective: str = ""
    engagement_name: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None


class SharedExploitMetadata(BaseModel):
    """Canonical exploit metadata shared across repos."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    name: str
    cve: str | None = None
    cwe_id: int | None = None
    msf_module: str = ""
    target_criteria: dict = {}  # type: ignore[type-arg]
    payload_type: str = ""
    success_criteria: str = ""
    risk_level: str = "moderate"
    author: str = ""
    source: str = ""


class SharedCredential(BaseModel):
    """Canonical credential model shared across repos."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    username: str
    domain: str = ""
    credential_type: str  # plaintext, ntlm_hash, kerberos_tgt, ssh_key
    value: str = ""
    source_host: str = ""
    source_method: str = ""  # kerberoast, sam_dump, config_file
    cracked_from: str = ""
    validated_hosts: list[str] = []
    discovered_at: datetime | None = None
