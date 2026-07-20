"""Tests for Finding model, Severity, FindingStatus, Evidence, DreadScore, Instance."""

from __future__ import annotations

from datetime import date, datetime

import pytest
from pydantic import ValidationError

from tarmo_vuln_core.models.finding import (
    DreadScore,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Instance,
    RuntimeTarget,
    Severity,
    SourceCodeRef,
)


def _minimal_finding(**overrides: object) -> Finding:
    """Create a Finding with minimal required fields, allowing overrides."""
    defaults: dict[str, object] = {
        "id": "test-finding",
        "title": "Test Finding",
        "severity": Severity.HIGH,
        "description": "A test finding.",
        "impact": "Test impact.",
        "remediation": "Test remediation.",
        "source_tool": "manual",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestSeverity:
    def test_ordering_critical_gt_high(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH

    def test_ordering_info_lt_low(self) -> None:
        assert Severity.INFO < Severity.LOW

    def test_ordering_medium_le_high(self) -> None:
        assert Severity.MEDIUM <= Severity.HIGH

    def test_ordering_high_ge_medium(self) -> None:
        assert Severity.HIGH >= Severity.MEDIUM

    def test_equality(self) -> None:
        assert Severity.HIGH == Severity.HIGH

    def test_inequality(self) -> None:
        assert Severity.HIGH != Severity.LOW

    def test_hashing_same_value(self) -> None:
        assert hash(Severity.HIGH) == hash(Severity.HIGH)

    def test_hashing_different_values(self) -> None:
        assert hash(Severity.HIGH) != hash(Severity.LOW)

    def test_sorting(self) -> None:
        unsorted = [Severity.MEDIUM, Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.LOW]
        result = sorted(unsorted)
        assert result == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_comparison_with_non_severity_returns_not_implemented(self) -> None:
        assert Severity.HIGH.__lt__("not a severity") is NotImplemented
        assert Severity.HIGH.__gt__("not a severity") is NotImplemented
        assert Severity.HIGH.__le__("not a severity") is NotImplemented
        assert Severity.HIGH.__ge__("not a severity") is NotImplemented
        assert Severity.HIGH.__eq__("not a severity") is NotImplemented


class TestFindingStatus:
    def test_all_eight_values(self) -> None:
        expected = {
            "open",
            "in_progress",
            "resolved",
            "verified",
            "risk_accepted",
            "false_positive",
            "mitigated",
            "provisional",
            "potential",  # add this
        }
        actual = {s.value for s in FindingStatus}
        assert actual == expected

    def test_open_is_default_string(self) -> None:
        assert FindingStatus.OPEN == "open"

    def test_provisional_value(self) -> None:
        assert FindingStatus.PROVISIONAL == "provisional"

    def test_potential_value(self) -> None:
        assert FindingStatus.POTENTIAL == "potential"


class TestEvidence:
    def test_auto_type_png(self) -> None:
        e = Evidence(filename="screenshot.png")
        assert e.type == EvidenceType.SCREENSHOT

    def test_auto_type_pcap(self) -> None:
        e = Evidence(filename="capture.pcap")
        assert e.type == EvidenceType.PCAP

    def test_auto_type_log(self) -> None:
        e = Evidence(filename="output.log")
        assert e.type == EvidenceType.LOG

    def test_auto_type_har(self) -> None:
        e = Evidence(filename="traffic.har")
        assert e.type == EvidenceType.HTTP

    def test_auto_type_pdf(self) -> None:
        e = Evidence(filename="report.pdf")
        assert e.type == EvidenceType.DOCUMENT

    def test_auto_type_unknown_extension(self) -> None:
        e = Evidence(filename="data.xyz")
        assert e.type == EvidenceType.OTHER

    def test_explicit_type_override(self) -> None:
        e = Evidence(filename="screenshot.png", type=EvidenceType.OTHER)
        assert e.type == EvidenceType.OTHER


class TestDreadScore:
    def test_total_computation(self) -> None:
        d = DreadScore(
            damage=8,
            reproducibility=6,
            exploitability=4,
            affected_users=2,
            discoverability=10,
        )
        assert d.total == (8 + 6 + 4 + 2 + 10) / 5

    def test_severity_critical(self) -> None:
        d = DreadScore(
            damage=10, reproducibility=10, exploitability=10, affected_users=10, discoverability=10
        )
        assert d.severity == Severity.CRITICAL

    def test_severity_high(self) -> None:
        d = DreadScore(
            damage=7, reproducibility=7, exploitability=7, affected_users=5, discoverability=6
        )
        assert d.severity == Severity.HIGH

    def test_severity_medium(self) -> None:
        d = DreadScore(
            damage=4, reproducibility=4, exploitability=4, affected_users=4, discoverability=4
        )
        assert d.severity == Severity.MEDIUM

    def test_severity_low(self) -> None:
        d = DreadScore(
            damage=1, reproducibility=1, exploitability=1, affected_users=1, discoverability=1
        )
        assert d.severity == Severity.LOW

    def test_range_validation_too_high(self) -> None:
        with pytest.raises(ValidationError, match="0-10"):
            DreadScore(
                damage=11,
                reproducibility=5,
                exploitability=5,
                affected_users=5,
                discoverability=5,
            )

    def test_range_validation_negative(self) -> None:
        with pytest.raises(ValidationError, match="0-10"):
            DreadScore(
                damage=-1,
                reproducibility=5,
                exploitability=5,
                affected_users=5,
                discoverability=5,
            )


class TestInstance:
    def test_minimal(self) -> None:
        inst = Instance(host="10.0.0.1")
        assert inst.host == "10.0.0.1"
        assert inst.status == FindingStatus.OPEN
        assert inst.port is None

    def test_full(self) -> None:
        inst = Instance(
            host="10.0.0.1",
            port=443,
            path="/admin",
            status=FindingStatus.VERIFIED,
            notes="Confirmed manually",
            verified_at=datetime(2026, 1, 15, 12, 0, 0),
        )
        assert inst.port == 443
        assert inst.path == "/admin"
        assert inst.status == FindingStatus.VERIFIED
        assert inst.notes == "Confirmed manually"

    def test_with_evidence(self) -> None:
        inst = Instance(
            host="10.0.0.1",
            evidence=[Evidence(filename="proof.png")],
        )
        assert len(inst.evidence) == 1
        assert inst.evidence[0].type == EvidenceType.SCREENSHOT


class TestFinding:
    def test_minimal_defaults(self) -> None:
        f = _minimal_finding()
        assert f.id == "test-finding"
        assert f.status == FindingStatus.OPEN
        assert f.cvss_score is None
        assert f.affected_hosts == []
        assert f.published is True

    def test_false_positive_status_forces_unpublished(self) -> None:
        """A retracted finding (status=FALSE_POSITIVE) must never be published."""
        f = _minimal_finding(status=FindingStatus.FALSE_POSITIVE, published=True)
        assert f.published is False

    def test_false_positive_bool_forces_unpublished(self) -> None:
        """The legacy false_positive bool also forces unpublished."""
        f = _minimal_finding(false_positive=True, published=True)
        assert f.published is False

    def test_open_finding_published_unchanged(self) -> None:
        """Non-FP findings keep their published flag."""
        f = _minimal_finding(status=FindingStatus.OPEN, published=True)
        assert f.published is True

    def test_cvss_range_valid(self) -> None:
        f = _minimal_finding(cvss_score=9.8)
        assert f.cvss_score == 9.8

    def test_cvss_range_invalid_too_high(self) -> None:
        with pytest.raises(ValidationError, match="0.0 and 10.0"):
            _minimal_finding(cvss_score=10.1)

    def test_cvss_range_invalid_negative(self) -> None:
        with pytest.raises(ValidationError, match="0.0 and 10.0"):
            _minimal_finding(cvss_score=-0.1)

    def test_owasp_range_valid(self) -> None:
        f = _minimal_finding(owasp_likelihood=5, owasp_impact=7)
        assert f.owasp_likelihood == 5
        assert f.owasp_impact == 7

    def test_owasp_range_invalid(self) -> None:
        with pytest.raises(ValidationError, match="1-9"):
            _minimal_finding(owasp_likelihood=0)

    def test_owasp_risk_score(self) -> None:
        f = _minimal_finding(owasp_likelihood=9, owasp_impact=9)
        assert f.owasp_risk_score == 9.0

    def test_owasp_risk_rating_critical(self) -> None:
        f = _minimal_finding(owasp_likelihood=9, owasp_impact=9)
        assert f.owasp_risk_rating == "CRITICAL"

    def test_owasp_risk_rating_none_when_missing(self) -> None:
        f = _minimal_finding()
        assert f.owasp_risk_score is None
        assert f.owasp_risk_rating is None

    def test_is_overdue_past_due(self) -> None:
        f = _minimal_finding(remediation_due=date(2020, 1, 1))
        assert f.is_overdue is True

    def test_is_overdue_future_due(self) -> None:
        f = _minimal_finding(remediation_due=date(2099, 1, 1))
        assert f.is_overdue is False

    def test_is_overdue_resolved_not_overdue(self) -> None:
        f = _minimal_finding(remediation_due=date(2020, 1, 1), status=FindingStatus.RESOLVED)
        assert f.is_overdue is False

    def test_is_overdue_none_not_overdue(self) -> None:
        f = _minimal_finding()
        assert f.is_overdue is False

    def test_is_provisional_expired(self) -> None:
        f = _minimal_finding(
            status=FindingStatus.PROVISIONAL,
            provisional_until=date(2020, 1, 1),
        )
        assert f.is_provisional_expired is True

    def test_is_provisional_not_expired(self) -> None:
        f = _minimal_finding(
            status=FindingStatus.PROVISIONAL,
            provisional_until=date(2099, 1, 1),
        )
        assert f.is_provisional_expired is False

    def test_is_provisional_non_provisional_status(self) -> None:
        f = _minimal_finding(provisional_until=date(2020, 1, 1))
        assert f.is_provisional_expired is False

    def test_content_hash_deterministic(self) -> None:
        f1 = _minimal_finding()
        f2 = _minimal_finding()
        assert f1.content_hash == f2.content_hash
        assert len(f1.content_hash) == 64  # SHA-256 hex

    def test_content_hash_changes_with_title(self) -> None:
        f1 = _minimal_finding(title="Title A")
        f2 = _minimal_finding(title="Title B")
        assert f1.content_hash != f2.content_hash

    def test_content_hash_changes_with_severity(self) -> None:
        f1 = _minimal_finding(severity=Severity.HIGH)
        f2 = _minimal_finding(severity=Severity.LOW)
        assert f1.content_hash != f2.content_hash

    def test_content_hash_changes_with_hosts(self) -> None:
        f1 = _minimal_finding(affected_hosts=["10.0.0.1"])
        f2 = _minimal_finding(affected_hosts=["10.0.0.2"])
        assert f1.content_hash != f2.content_hash

    def test_content_hash_host_order_independent(self) -> None:
        f1 = _minimal_finding(affected_hosts=["10.0.0.2", "10.0.0.1"])
        f2 = _minimal_finding(affected_hosts=["10.0.0.1", "10.0.0.2"])
        assert f1.content_hash == f2.content_hash

    def test_serialization_roundtrip(self) -> None:
        f = _minimal_finding(
            cvss_score=7.5,
            affected_hosts=["10.0.0.1"],
            instances=[Instance(host="10.0.0.1", port=443)],
        )
        data = f.model_dump()
        f2 = Finding(**data)
        assert f2.id == f.id
        assert f2.cvss_score == f.cvss_score
        assert f2.instances[0].port == 443
        assert f2.content_hash == f.content_hash


class TestSourceCodeRef:
    def test_minimal_source_code_ref(self) -> None:
        ref = SourceCodeRef(file_path="src/auth/login.py")
        assert ref.file_path == "src/auth/login.py"
        assert ref.start_line is None
        assert ref.end_line is None
        assert ref.snippet == ""

    def test_full_source_code_ref(self) -> None:
        ref = SourceCodeRef(
            file_path="src/auth/login.py",
            start_line=42,
            end_line=45,
            snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            repository="github.com/org/repo",
            branch="main",
            commit_sha="abc123",
        )
        assert ref.file_path == "src/auth/login.py"
        assert ref.start_line == 42
        assert ref.end_line == 45
        assert "cursor.execute" in ref.snippet
        assert ref.repository == "github.com/org/repo"
        assert ref.branch == "main"
        assert ref.commit_sha == "abc123"

    def test_whitespace_stripped(self) -> None:
        ref = SourceCodeRef(file_path="  src/auth/login.py  ")
        assert ref.file_path == "src/auth/login.py"

    def test_column_and_symbol_default_none(self) -> None:
        ref = SourceCodeRef(file_path="src/app.py", start_line=10)
        assert ref.column is None
        assert ref.symbol is None

    def test_column_and_symbol_set(self) -> None:
        ref = SourceCodeRef(
            file_path="src/app.py",
            start_line=42,
            column=17,
            symbol="execute_query",
        )
        assert ref.column == 17
        assert ref.symbol == "execute_query"

    def test_is_sink_defaults_true(self) -> None:
        # Default: single-ref findings (Semgrep, Bandit, CodeQL) are sinks.
        ref = SourceCodeRef(file_path="src/app.py", start_line=10)
        assert ref.is_sink is True

    def test_is_sink_false_for_taint_source(self) -> None:
        # Checkmarx taint-chain source nodes mark themselves non-sink.
        ref = SourceCodeRef(
            file_path="src/request_handler.py",
            start_line=5,
            symbol="request.args",
            is_sink=False,
        )
        assert ref.is_sink is False
        assert ref.symbol == "request.args"

    def test_serialization_roundtrip_with_new_fields(self) -> None:
        ref = SourceCodeRef(
            file_path="src/app.py",
            start_line=42,
            column=17,
            symbol="execute_query",
            is_sink=True,
        )
        data = ref.model_dump()
        ref2 = SourceCodeRef(**data)
        assert ref2.column == 17
        assert ref2.symbol == "execute_query"
        assert ref2.is_sink is True


class TestRuntimeTarget:
    def test_defaults(self) -> None:
        target = RuntimeTarget()
        assert target.url == ""
        assert target.method == ""
        assert target.confidence == "low"
        assert target.test_payloads == []
        assert target.port is None

    def test_full_runtime_target(self) -> None:
        target = RuntimeTarget(
            url="/api/login",
            method="POST",
            parameter="username",
            host="10.0.0.1",
            port=8080,
            protocol="https",
            test_payloads=["' OR 1=1--", "admin' --"],
            confidence="high",
            notes="SQLi in login form",
        )
        assert target.url == "/api/login"
        assert target.method == "POST"
        assert target.parameter == "username"
        assert target.host == "10.0.0.1"
        assert target.port == 8080
        assert target.protocol == "https"
        assert len(target.test_payloads) == 2
        assert target.test_payloads[0] == "' OR 1=1--"
        assert target.confidence == "high"
        assert "SQLi" in target.notes


class TestFindingSourceCodeRefs:
    def test_source_code_refs_defaults_empty(self) -> None:
        f = _minimal_finding()
        assert f.source_code_refs == []

    def test_finding_with_source_code_refs(self) -> None:
        ref = SourceCodeRef(file_path="src/app.py", start_line=10)
        f = _minimal_finding(source_code_refs=[ref])
        assert len(f.source_code_refs) == 1
        assert f.source_code_refs[0].file_path == "src/app.py"
        assert f.source_code_refs[0].start_line == 10

    def test_runtime_targets_defaults_empty(self) -> None:
        f = _minimal_finding()
        assert f.runtime_targets == []

    def test_finding_with_runtime_targets(self) -> None:
        target = RuntimeTarget(url="/api/login", method="POST", confidence="high")
        f = _minimal_finding(runtime_targets=[target])
        assert len(f.runtime_targets) == 1
        assert f.runtime_targets[0].url == "/api/login"
        assert f.runtime_targets[0].confidence == "high"

    def test_serialization_roundtrip_with_refs(self) -> None:
        ref = SourceCodeRef(file_path="src/app.py", start_line=10, snippet="bad()")
        target = RuntimeTarget(url="/api/v1", method="GET", confidence="medium")
        f = _minimal_finding(source_code_refs=[ref], runtime_targets=[target])
        data = f.model_dump()
        f2 = Finding(**data)
        assert f2.source_code_refs[0].file_path == "src/app.py"
        assert f2.source_code_refs[0].snippet == "bad()"
        assert f2.runtime_targets[0].url == "/api/v1"
        assert f2.runtime_targets[0].confidence == "medium"
