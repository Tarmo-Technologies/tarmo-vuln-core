"""Test that Finding.methodology_items field exists and round-trips."""

from tarmo_vuln_core.models.finding import Finding


def test_methodology_items_default_empty() -> None:
    """Finding.methodology_items defaults to an empty list."""
    f = Finding(
        id="test-finding",
        title="Test",
        severity="HIGH",
        description="desc",
        impact="impact",
        remediation="fix it",
        source_tool="manual",
    )
    assert f.methodology_items == []


def test_methodology_items_round_trip() -> None:
    """methodology_items survives JSON serialization and deserialization."""
    items = ["INPV-01", "SESS-03"]
    f = Finding(
        id="test-finding",
        title="Test",
        severity="HIGH",
        description="desc",
        impact="impact",
        remediation="fix it",
        source_tool="manual",
        methodology_items=items,
    )
    assert f.methodology_items == items

    # Round-trip through JSON
    json_str = f.model_dump_json()
    restored = Finding.model_validate_json(json_str)
    assert restored.methodology_items == items


def test_methodology_items_in_dict_dump() -> None:
    """methodology_items appears in model_dump output."""
    f = Finding(
        id="test-finding",
        title="Test",
        severity="HIGH",
        description="desc",
        impact="impact",
        remediation="fix it",
        source_tool="manual",
        methodology_items=["CRYP-02"],
    )
    d = f.model_dump()
    assert d["methodology_items"] == ["CRYP-02"]
