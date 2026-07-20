"""Host model and related types."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class HostProperty(BaseModel):
    """A single key-value metadata property for a discovered host."""

    model_config = ConfigDict(str_strip_whitespace=True)

    key: str
    value: str


class Host(BaseModel):
    """A discovered network host with structured metadata."""

    model_config = ConfigDict(str_strip_whitespace=True)

    address: str
    hostnames: list[str] = []
    os: str | None = None
    os_confidence: int | None = None
    mac: str | None = None
    properties: list[HostProperty] = []
    notes: str = ""
