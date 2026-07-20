"""Tests for StatusWorkflow."""

from __future__ import annotations

from tarmo_vuln_core.models import FindingStatus
from tarmo_vuln_core.workflow import StatusWorkflow


class TestStatusWorkflow:
    def test_valid_transition_open_to_in_progress(self) -> None:
        wf = StatusWorkflow()
        assert wf.can_transition(FindingStatus.OPEN, FindingStatus.IN_PROGRESS) is True

    def test_invalid_transition_open_to_resolved(self) -> None:
        wf = StatusWorkflow()
        assert wf.can_transition(FindingStatus.OPEN, FindingStatus.RESOLVED) is False

    def test_enforce_false_allows_all(self) -> None:
        wf = StatusWorkflow(enforce=False)
        assert wf.can_transition(FindingStatus.OPEN, FindingStatus.RESOLVED) is True
        assert wf.can_transition(FindingStatus.VERIFIED, FindingStatus.MITIGATED) is True

    def test_allowed_next_for_open(self) -> None:
        wf = StatusWorkflow()
        nexts = wf.allowed_next(FindingStatus.OPEN)
        assert len(nexts) == 3
        assert FindingStatus.IN_PROGRESS in nexts
        assert FindingStatus.FALSE_POSITIVE in nexts
        assert FindingStatus.RISK_ACCEPTED in nexts

    def test_status_not_in_dict_allows_any(self) -> None:
        wf = StatusWorkflow(allowed_transitions={})
        assert wf.can_transition(FindingStatus.OPEN, FindingStatus.RESOLVED) is True

    def test_default_transitions_not_shared_between_instances(self) -> None:
        wf1 = StatusWorkflow()
        wf2 = StatusWorkflow()
        wf1.allowed_transitions["open"].append("verified")
        assert "verified" not in wf2.allowed_transitions["open"]

    def test_allowed_next_resolved(self) -> None:
        wf = StatusWorkflow()
        nexts = wf.allowed_next(FindingStatus.RESOLVED)
        assert len(nexts) == 2
        assert FindingStatus.VERIFIED in nexts
        assert FindingStatus.OPEN in nexts

    def test_can_transition_in_progress_to_resolved(self) -> None:
        wf = StatusWorkflow()
        assert wf.can_transition(FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED) is True

    def test_can_transition_in_progress_to_verified_invalid(self) -> None:
        wf = StatusWorkflow()
        assert wf.can_transition(FindingStatus.IN_PROGRESS, FindingStatus.VERIFIED) is False
