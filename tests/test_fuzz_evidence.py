"""FuzzEvidence / StackFrame models and Finding.fuzz."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tarmo_vuln_core import Finding, FuzzEvidence, Severity, StackFrame


@pytest.mark.unit
class TestStackFrame:
    def test_all_fields_optional(self) -> None:
        frame = StackFrame()
        assert (frame.file, frame.function, frame.line) == (None, None, None)

    def test_values_round_trip(self) -> None:
        frame = StackFrame(file="parse.c", function="parse_record", line=9)
        assert frame.model_dump() == {"file": "parse.c", "function": "parse_record", "line": 9}


@pytest.mark.unit
class TestFuzzEvidence:
    def test_requires_engine_and_finding_id(self) -> None:
        with pytest.raises(ValidationError, match="finding_id"):
            FuzzEvidence(engine="bhf")  # type: ignore[call-arg]

    def test_defaults(self) -> None:
        ev = FuzzEvidence(engine="bhf", finding_id="F-0000-c0dca483")
        assert ev.member_ids == []
        assert ev.stack == []
        assert ev.cwe_ids == []
        assert ev.prosthetics_used is None
        assert ev.reproducer_path is None

    def test_list_defaults_are_not_shared(self) -> None:
        a = FuzzEvidence(engine="bhf", finding_id="A")
        b = FuzzEvidence(engine="bhf", finding_id="B")
        a.cwe_ids.append(122)
        assert b.cwe_ids == []

    def test_full_payload(self) -> None:
        ev = FuzzEvidence(
            engine="bhf",
            finding_id="F-0000-c0dca483",
            rule_id="BHF-201",
            exception_name="ASAN_HEAP_BUFFER_OVERFLOW",
            sanitizer="asan",
            classification="unhandled",
            verdict="likely_reachable",
            confidence="medium",
            confirmation="fuzz",
            harness_id="H-C0005-3B81D475",
            cluster_key="cc6b46c403134e69",
            signature="c0dca483",
            member_ids=["F-0009-aaaa"],
            stack=[{"file": "parse.c", "function": "parse_record", "line": 9}],
            reproducer_path="findings/F-0000-c0dca483/testcase.bin",
            replay_command="bhf replay --finding findings/F-0000-c0dca483",
            prosthetics_used=False,
            cwe_ids=[122, 125],
        )
        assert ev.stack[0] == StackFrame(file="parse.c", function="parse_record", line=9)
        assert ev.cwe_ids == [122, 125]


@pytest.mark.unit
class TestFindingFuzzField:
    def test_default_none(self) -> None:
        assert Finding(title="t", severity=Severity.LOW).fuzz is None

    def test_json_round_trip(self) -> None:
        f = Finding(
            title="Heap-based Buffer Overflow in parse_record",
            severity=Severity.CRITICAL,
            fuzz=FuzzEvidence(engine="bhf", finding_id="F-0000", cwe_ids=[122]),
        )
        restored = Finding.model_validate_json(f.model_dump_json())
        assert restored.fuzz is not None
        assert restored.fuzz.finding_id == "F-0000"
        assert restored.fuzz.cwe_ids == [122]

    def test_models_package_exports(self) -> None:
        import tarmo_vuln_core
        from tarmo_vuln_core import models

        assert models.FuzzEvidence is FuzzEvidence
        assert models.StackFrame is StackFrame
        assert {"FuzzEvidence", "StackFrame"} <= set(tarmo_vuln_core.__all__)
