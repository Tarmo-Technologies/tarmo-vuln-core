"""Finding.data_flows: the FlowStep / DataFlow models, their limits and serialization (#8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tarmo_vuln_core import models
from tarmo_vuln_core.models import DataFlow, Finding, FlowStep, Severity
from tarmo_vuln_core.models.finding import plain_identifier


def _step(line: int, role: str = "step", **kwargs: object) -> FlowStep:
    return FlowStep(
        file_path="src/app.c",
        start_line=line,
        role=role,  # type: ignore[arg-type]
        origin="sarif_code_flow",
        **kwargs,  # type: ignore[arg-type]
    )


def _flow(n: int) -> DataFlow:
    """A flow of *n* steps on lines 1..n: source first, sink last."""
    roles = ["source"] + ["step"] * (n - 2) + ["sink"]
    return DataFlow(steps=[_step(i + 1, role) for i, role in enumerate(roles)])


def _finding(**kwargs: object) -> Finding:
    return Finding(id="f-1", title="T", severity=Severity.HIGH, **kwargs)  # type: ignore[arg-type]


@pytest.mark.unit
class TestPlainIdentifier:
    @pytest.mark.parametrize(
        "text", ["username", "_x1", "req.args", "self->buf", "std::string", "a.b->c::d"]
    )
    def test_identifiers_and_member_access_are_kept(self, text: str) -> None:
        assert plain_identifier(text) == text

    def test_surrounding_whitespace_is_stripped(self) -> None:
        assert plain_identifier("  buf \n") == "buf"

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "ControlFlowNode for request",
            "getenv(...)",
            "call to getenv",
            "args : String[]",
            "1abc",
            "a.",
            "a..b",
            "<anonymous>",
            "x;rm -rf /",
            "a.b\nc",
            None,
        ],
    )
    def test_free_text_is_not_a_symbol(self, text: str | None) -> None:
        assert plain_identifier(text) is None

    def test_at_most_64_characters(self) -> None:
        assert plain_identifier("a" * 64) == "a" * 64
        assert plain_identifier("a" * 65) is None


@pytest.mark.unit
class TestFlowStep:
    def test_defaults(self) -> None:
        step = FlowStep(file_path="a.c", role="sink", origin="coverity_event")
        assert step.model_dump() == {
            "file_path": "a.c",
            "start_line": None,
            "column": None,
            "symbol": None,
            "message": "",
            "role": "sink",
            "tool_kind": None,
            "origin": "coverity_event",
        }

    def test_unknown_role_rejected(self) -> None:
        with pytest.raises(ValidationError, match="role"):
            FlowStep(file_path="a.c", role="taint", origin="sarif_code_flow")  # type: ignore[arg-type]

    def test_symbol_must_be_a_plain_identifier(self) -> None:
        with pytest.raises(ValidationError, match="plain identifier"):
            _step(1, symbol="call to getenv")

    def test_identifier_symbol_accepted(self) -> None:
        assert _step(1, symbol="req.args").symbol == "req.args"

    @pytest.mark.parametrize("value", [0, -1, 2**31])
    def test_line_or_column_outside_1_to_int32_max_becomes_none(self, value: int) -> None:
        """Scanners write ``line="0"`` (cppcheck) or ``startLine: 0`` for "unknown"; a
        consumer reading ``lines[line - 1]`` would silently read the last line."""
        step = FlowStep(
            file_path="a.c", start_line=value, column=value, role="sink", origin="cppcheck_location"
        )
        assert (step.start_line, step.column) == (None, None)

    def test_line_and_column_from_1_to_int32_max_kept(self) -> None:
        step = _step(1, column=2**31 - 1)
        assert (step.start_line, step.column) == (1, 2**31 - 1)
        again = FlowStep.model_validate(step.model_dump(mode="json"))
        assert (again.start_line, again.column) == (1, 2**31 - 1)


@pytest.mark.unit
class TestDataFlow:
    def test_flow_without_source_is_valid(self) -> None:
        flow = DataFlow(steps=[_step(1), _step(2, "sink")])
        assert [s.role for s in flow.steps] == ["step", "sink"]
        assert flow.truncated is False

    def test_empty_flow_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least one step"):
            DataFlow(steps=[])

    def test_sink_must_be_last(self) -> None:
        with pytest.raises(ValidationError, match="last step must be the sink"):
            DataFlow(steps=[_step(1, "sink"), _step(2)])

    def test_only_the_last_step_is_a_sink(self) -> None:
        with pytest.raises(ValidationError, match="only the last step"):
            DataFlow(steps=[_step(1, "sink"), _step(2, "sink")])

    def test_source_only_first(self) -> None:
        with pytest.raises(ValidationError, match="only the first step"):
            DataFlow(steps=[_step(1), _step(2, "source"), _step(3, "sink")])

    def test_32_steps_are_kept_whole(self) -> None:
        flow = _flow(32)
        assert [s.start_line for s in flow.steps] == list(range(1, 33))
        assert flow.truncated is False

    def test_longer_flow_keeps_first_16_and_last_16(self) -> None:
        flow = _flow(40)
        assert [s.start_line for s in flow.steps] == list(range(1, 17)) + list(range(25, 41))
        assert flow.truncated is True
        assert (flow.steps[0].role, flow.steps[-1].role) == ("source", "sink")

    def test_truncated_flow_round_trips(self) -> None:
        flow = _flow(40)
        again = DataFlow.model_validate(flow.model_dump(mode="json"))
        assert again == flow
        assert (len(again.steps), again.truncated) == (32, True)


@pytest.mark.unit
class TestFindingDataFlows:
    def test_default_is_empty(self) -> None:
        assert _finding().data_flows == []

    def test_at_most_three_flows_are_kept(self) -> None:
        f = _finding(data_flows=[_flow(n) for n in (2, 3, 4, 5, 6)])
        assert [len(flow.steps) for flow in f.data_flows] == [2, 3, 4]

    def test_model_dump_json_includes_data_flows(self) -> None:
        dump = _finding(data_flows=[_flow(2)]).model_dump(mode="json")
        assert dump["data_flows"] == [
            {
                "steps": [
                    {
                        "file_path": "src/app.c",
                        "start_line": 1,
                        "column": None,
                        "symbol": None,
                        "message": "",
                        "role": "source",
                        "tool_kind": None,
                        "origin": "sarif_code_flow",
                    },
                    {
                        "file_path": "src/app.c",
                        "start_line": 2,
                        "column": None,
                        "symbol": None,
                        "message": "",
                        "role": "sink",
                        "tool_kind": None,
                        "origin": "sarif_code_flow",
                    },
                ],
                "truncated": False,
            }
        ]

    def test_json_round_trip(self) -> None:
        step = _step(7, "sink", column=3, symbol="buf", message="buf", tool_kind="taint")
        f = _finding(data_flows=[DataFlow(steps=[_step(1, "source"), step]), _flow(40)])
        dump = f.model_dump(mode="json")
        again = Finding.model_validate(dump)
        assert again.data_flows == f.data_flows
        assert again.model_dump(mode="json") == dump

    def test_dump_without_data_flows_still_validates(self) -> None:
        dump = _finding(affected_hosts=["src/app.c"]).model_dump(mode="json")
        del dump["data_flows"]
        again = Finding.model_validate(dump)
        assert again.data_flows == []
        assert (again.id, again.affected_hosts) == ("f-1", ["src/app.c"])

    def test_content_hash_ignores_data_flows(self) -> None:
        assert _finding(data_flows=[_flow(3)]).content_hash == _finding().content_hash

    def test_models_package_exports_the_flow_models(self) -> None:
        assert {"DataFlow", "FlowStep"} <= set(models.__all__)
