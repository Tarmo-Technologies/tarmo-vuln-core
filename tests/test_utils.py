"""Tests for tarmo_vuln_core.utils."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from tarmo_vuln_core.utils import detect_language, get_xml_text, severity_from_cvss, slugify


class TestSlugify:
    """Tests for the slugify utility function."""

    def test_basic_conversion(self) -> None:
        assert slugify("SQL Injection (CWE-89)") == "sql-injection-cwe-89"

    def test_strips_leading_trailing_hyphens(self) -> None:
        assert slugify("  --leading/trailing--  ") == "leading-trailing"

    def test_empty_string(self) -> None:
        assert slugify("") == ""

    def test_all_special_chars(self) -> None:
        assert slugify("!!!@@@###") == ""

    def test_preserves_numbers(self) -> None:
        assert slugify("CVE-2024-12345") == "cve-2024-12345"

    def test_collapses_multiple_separators(self) -> None:
        assert slugify("foo   bar___baz") == "foo-bar-baz"

    def test_unicode_stripped(self) -> None:
        assert slugify("héllo wörld") == "h-llo-w-rld"

    def test_single_word(self) -> None:
        assert slugify("nmap") == "nmap"


class TestGetXmlText:
    """Tests for the get_xml_text utility function."""

    def test_returns_child_text(self) -> None:
        root = ET.fromstring("<root><name>Hello</name></root>")
        assert get_xml_text(root, "name") == "Hello"

    def test_strips_whitespace(self) -> None:
        root = ET.fromstring("<root><name>  padded  </name></root>")
        assert get_xml_text(root, "name") == "padded"

    def test_returns_fallback_for_missing_tag(self) -> None:
        root = ET.fromstring("<root></root>")
        assert get_xml_text(root, "missing", "default") == "default"

    def test_returns_empty_string_default_fallback(self) -> None:
        root = ET.fromstring("<root></root>")
        assert get_xml_text(root, "missing") == ""

    def test_returns_fallback_for_empty_text(self) -> None:
        root = ET.fromstring("<root><name></name></root>")
        assert get_xml_text(root, "name", "fallback") == "fallback"


class TestDetectLanguage:
    """Tests for detect_language utility."""

    def test_python(self) -> None:
        assert detect_language("src/main.py") == "Python"

    def test_c(self) -> None:
        assert detect_language("lib/parser.c") == "C"

    def test_c_header(self) -> None:
        assert detect_language("include/parser.h") == "C"

    def test_cpp(self) -> None:
        assert detect_language("src/engine.cpp") == "C++"

    def test_cpp_cc(self) -> None:
        assert detect_language("src/engine.cc") == "C++"

    def test_java(self) -> None:
        assert detect_language("src/App.java") == "Java"

    def test_javascript(self) -> None:
        assert detect_language("src/index.js") == "JavaScript"

    def test_typescript(self) -> None:
        assert detect_language("src/app.ts") == "TypeScript"

    def test_ada_adb(self) -> None:
        assert detect_language("src/comms.adb") == "Ada"

    def test_ada_ads(self) -> None:
        assert detect_language("src/comms.ads") == "Ada"

    def test_vhdl(self) -> None:
        assert detect_language("src/top.vhd") == "VHDL"

    def test_verilog(self) -> None:
        assert detect_language("src/alu.v") == "Verilog"

    def test_systemverilog(self) -> None:
        assert detect_language("src/alu.sv") == "SystemVerilog"

    def test_go(self) -> None:
        assert detect_language("cmd/main.go") == "Go"

    def test_rust(self) -> None:
        assert detect_language("src/lib.rs") == "Rust"

    def test_ruby(self) -> None:
        assert detect_language("app/models/user.rb") == "Ruby"

    def test_php(self) -> None:
        assert detect_language("src/index.php") == "PHP"

    def test_csharp(self) -> None:
        assert detect_language("Controllers/UserController.cs") == "C#"

    def test_swift(self) -> None:
        assert detect_language("Sources/App.swift") == "Swift"

    def test_kotlin(self) -> None:
        assert detect_language("src/Main.kt") == "Kotlin"

    def test_unknown_extension(self) -> None:
        assert detect_language("data/config.xyz") is None

    def test_no_extension(self) -> None:
        assert detect_language("Makefile") is None

    def test_case_insensitive(self) -> None:
        assert detect_language("src/Main.PY") == "Python"


class TestSeverityFromCvss:
    """Tests for CVSS v3.1 severity bands (NIST NVD standard)."""

    def test_zero_is_info(self) -> None:
        assert severity_from_cvss(0.0) == "INFO"

    def test_negative_is_info(self) -> None:
        assert severity_from_cvss(-1.0) == "INFO"

    def test_low_boundary_start(self) -> None:
        assert severity_from_cvss(0.1) == "LOW"

    def test_low_boundary_end(self) -> None:
        assert severity_from_cvss(3.9) == "LOW"

    def test_medium_boundary_start(self) -> None:
        assert severity_from_cvss(4.0) == "MEDIUM"

    def test_medium_boundary_end(self) -> None:
        assert severity_from_cvss(6.9) == "MEDIUM"

    def test_high_boundary_start(self) -> None:
        assert severity_from_cvss(7.0) == "HIGH"

    def test_high_boundary_end(self) -> None:
        assert severity_from_cvss(8.9) == "HIGH"

    def test_critical_boundary_start(self) -> None:
        assert severity_from_cvss(9.0) == "CRITICAL"

    def test_critical_max(self) -> None:
        assert severity_from_cvss(10.0) == "CRITICAL"

    def test_mid_range_values(self) -> None:
        assert severity_from_cvss(2.5) == "LOW"
        assert severity_from_cvss(5.5) == "MEDIUM"
        assert severity_from_cvss(7.5) == "HIGH"
        assert severity_from_cvss(9.8) == "CRITICAL"
