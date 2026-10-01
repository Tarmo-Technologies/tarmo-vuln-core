"""Build ``Finding.data_flows`` from the path locations a scanner reports."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from tarmo_vuln_core.models import DataFlow, FlowStep
from tarmo_vuln_core.models.finding import plain_identifier


@dataclass(frozen=True)
class FlowPoint:
    """One located point of a scanner path, in flow order, before roles are given."""

    file_path: str
    start_line: int | None = None
    column: int | None = None
    message: str = ""
    tool_kind: str | None = None


def build_data_flow(
    points: Sequence[FlowPoint], *, origin: str, has_source: bool
) -> DataFlow | None:
    """Return a :class:`DataFlow` over *points*, or None for fewer than two points.

    The last point is the sink. With *has_source* the first point is the
    source (SARIF codeFlows, Checkmarx paths); otherwise it is a step
    (Coverity events, cppcheck locations). A single point is only the sink,
    which the finding's sink ref already gives, so it is not a flow. The
    symbol is set only when the point's message is a plain identifier.
    """
    if len(points) < 2:
        return None
    last = len(points) - 1
    steps: list[FlowStep] = []
    for i, point in enumerate(points):
        role: Literal["source", "step", "sink"]
        if i == last:
            role = "sink"
        elif i == 0 and has_source:
            role = "source"
        else:
            role = "step"
        steps.append(
            FlowStep(
                file_path=point.file_path,
                start_line=point.start_line,
                column=point.column,
                symbol=plain_identifier(point.message),
                message=point.message,
                role=role,
                tool_kind=point.tool_kind,
                origin=origin,
            )
        )
    return DataFlow(steps=steps)
