"""Shared utility helpers used across ingestors and other modules."""

from __future__ import annotations

import re
from xml.etree.ElementTree import Element


def slugify(text: str) -> str:
    """Convert free-form text to a filesystem-safe, URL-safe slug.

    Examples:
        >>> slugify("SQL Injection (CWE-89)")
        'sql-injection-cwe-89'
        >>> slugify("  --leading/trailing--  ")
        'leading-trailing'
    """
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower())
    return slug.strip("-")


_EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".ada": "Ada",
    ".adb": "Ada",
    ".ads": "Ada",
    ".vhd": "VHDL",
    ".vhdl": "VHDL",
    ".v": "Verilog",
    ".sv": "SystemVerilog",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
}


def detect_language(file_path: str) -> str | None:
    """Detect programming language from a file path's extension.

    Returns the language name or None if the extension is not recognized.
    Case-insensitive.
    """
    dot = file_path.rfind(".")
    if dot < 0:
        return None
    ext = file_path[dot:].lower()
    return _EXTENSION_LANGUAGE_MAP.get(ext)


def severity_from_cvss(score: float) -> str:
    """Derive qualitative severity from a CVSS v3.1 base score.

    Uses the NIST NVD standard bands (FIRST.org CVSS v3.1 spec):
        0.0       → INFO
        0.1 – 3.9 → LOW
        4.0 – 6.9 → MEDIUM
        7.0 – 8.9 → HIGH
        9.0 – 10.0 → CRITICAL
    """
    if score <= 0.0:
        return "INFO"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def get_xml_text(el: Element, tag: str, fallback: str = "") -> str:
    """Return stripped text content of a child element, or *fallback* if absent."""
    child = el.find(tag)
    return (child.text or fallback).strip() if child is not None else fallback
