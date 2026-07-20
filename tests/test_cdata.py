"""Tests for CData mapping registry."""

from pathlib import Path


class TestCDataRegistry:
    """Test CDataRegistry lookup functionality."""

    def test_checkmarx_lookup_returns_correct_cwe(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("checkmarx", "Reflected_XSS")
        assert match is not None
        assert match.cwe == 79

    def test_checkmarx_lookup_includes_severity(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("checkmarx", "Reflected_XSS")
        assert match is not None
        assert match.severity == "High"

    def test_cppcheck_lookup_returns_correct_cwe(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("cppcheck", "allocaCalled")
        assert match is not None
        assert match.cwe == 676

    def test_cppcheck_lookup_with_confidence(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("cppcheck", "arrayIndexThenCheck")
        assert match is not None
        assert match.cwe == 710
        assert match.confidence == "Inform"

    def test_eslint_lookup_returns_correct_cwe(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("eslint", "no-undef")
        assert match is not None
        assert match.cwe == 457

    def test_pylint_lookup_returns_correct_cwe(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("pylint", "E0110")
        assert match is not None
        assert match.cwe == 758

    def test_sigasi_vhdl_lookup_uses_compound_key(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("sigasi", "vhdl:1")
        assert match is not None
        assert match.cwe == 681

    def test_sigasi_verilog_lookup_uses_compound_key(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("sigasi", "verilog:1")
        assert match is not None
        assert match.cwe == 1071

    def test_imported_cppcheck_lookup_returns_csv_value(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("cppcheck", "redundantAssignment")
        assert match is not None
        assert match.cwe == 563
        assert match.confidence == "Inform"

    def test_imported_srm_lookup_returns_csv_value(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("srm", "Dead Code")
        assert match is not None
        assert match.cwe == 561
        assert match.confidence == "Inform"

    def test_unknown_query_returns_none(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("checkmarx", "Nonexistent_Query_12345")
        assert match is None

    def test_unknown_tool_returns_none(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        match = registry.lookup("unknown_tool", "some_query")
        assert match is None

    def test_user_override_takes_precedence(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        overrides = [
            {"tool": "checkmarx", "query": "Reflected_XSS", "cwe": 999, "confidence": "Override"}
        ]
        match = registry.lookup("checkmarx", "Reflected_XSS", overrides=overrides)
        assert match is not None
        assert match.cwe == 999
        assert match.confidence == "Override"

    def test_user_override_without_match_falls_through(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        overrides = [{"tool": "checkmarx", "query": "Other_Query", "cwe": 999}]
        match = registry.lookup("checkmarx", "Reflected_XSS", overrides=overrides)
        assert match is not None
        assert match.cwe == 79  # falls through to built-in

    def test_cdata_match_fields(self) -> None:
        from tarmo_vuln_core.cdata import CDataMatch

        match = CDataMatch(cwe=79, confidence="Confirmed", severity="High")
        assert match.cwe == 79
        assert match.confidence == "Confirmed"
        assert match.severity == "High"

    def test_cdata_match_optional_fields(self) -> None:
        from tarmo_vuln_core.cdata import CDataMatch

        match = CDataMatch(cwe=79)
        assert match.cwe == 79
        assert match.confidence is None
        assert match.severity is None

    def test_mitre_category_lookup(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        assert registry.mitre_category(0) == "NOTFOUND"
        assert registry.mitre_category(19) == "CATEGORY"
        assert registry.mitre_category(391) == "DEPRECATED"
        assert registry.mitre_category(99999) is None

    def test_registry_is_singleton_like(self) -> None:
        """Verify that the default registry is reused (module-level instance)."""
        from tarmo_vuln_core.cdata import default_registry

        r1 = default_registry()
        r2 = default_registry()
        assert r1 is r2

    def test_all_tools_have_entries(self) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        for tool in ["checkmarx", "cppcheck", "eslint", "pylint", "sigasi", "srm"]:
            assert len(registry._mappings.get(tool, {})) > 0, f"No entries for {tool}"

    def test_registry_discovers_new_tool_file(self, tmp_path: Path) -> None:
        from tarmo_vuln_core.cdata import CDataRegistry

        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        (mappings_dir / "srm.json").write_text('{"Dead Code": {"cwe": 561}}', encoding="utf-8")
        (mappings_dir / "mitre_cwe_categories.json").write_text("{}", encoding="utf-8")

        registry = CDataRegistry(mappings_dir=mappings_dir)
        match = registry.lookup("srm", "Dead Code")

        assert match is not None
        assert match.cwe == 561

    def test_checkmarx_dedup_removes_language_duplicates(self) -> None:
        """Verify that Checkmarx entries are deduped (one per query, not per lang)."""
        from tarmo_vuln_core.cdata import CDataRegistry

        registry = CDataRegistry()
        # Reflected_XSS appears in many languages but should be single entry
        count = sum(1 for q in registry._mappings.get("checkmarx", {}) if q == "Reflected_XSS")
        assert count == 1
