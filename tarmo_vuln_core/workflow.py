"""StatusWorkflow — finding status transition enforcement."""

from __future__ import annotations

import contextlib

from pydantic import BaseModel, Field

from tarmo_vuln_core.models import FindingStatus

DEFAULT_TRANSITIONS: dict[str, list[str]] = {
    "open": ["in_progress", "false_positive", "risk_accepted"],
    "in_progress": ["resolved", "mitigated", "risk_accepted", "open"],
    "resolved": ["verified", "open"],
    "verified": ["open"],
    "risk_accepted": ["open"],
    "false_positive": ["open"],
    "mitigated": ["open", "verified"],
    "provisional": ["open", "resolved"],
}


class StatusWorkflow(BaseModel):
    """Allowed finding status transitions for workflow enforcement."""

    allowed_transitions: dict[str, list[str]] = Field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_TRANSITIONS.items()}
    )
    enforce: bool = True

    def allowed_next(self, current: FindingStatus) -> list[FindingStatus]:
        """Return the list of statuses reachable from current."""
        names = self.allowed_transitions.get(current.value, [])
        result: list[FindingStatus] = []
        for n in names:
            with contextlib.suppress(ValueError):
                result.append(FindingStatus(n))
        return result

    def can_transition(self, current: FindingStatus, target: FindingStatus) -> bool:
        """Return True if current -> target is allowed (or enforcement is off)."""
        if not self.enforce:
            return True
        if current.value not in self.allowed_transitions:
            return True
        return target.value in self.allowed_transitions[current.value]
