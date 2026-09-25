"""Binary strings and binwalk output ingestor.

Parses output from `strings` and `binwalk` commands run against binaries
to identify hardcoded secrets, URLs, credentials, and embedded artifacts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

# Pattern categories for strings analysis
_PATTERNS: list[tuple[str, str, Severity, int, re.Pattern[str]]] = [
    (
        "hardcoded-url",
        "Hardcoded URLs in Binary",
        Severity.LOW,
        798,
        re.compile(r"https?://[^\s\"'<>]{10,}", re.IGNORECASE),
    ),
    (
        "hardcoded-email",
        "Email Addresses in Binary",
        Severity.LOW,
        200,
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
    ),
    (
        "api-key-pattern",
        "Potential API Key in Binary",
        Severity.HIGH,
        798,
        re.compile(
            r"(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|"
            r"ghp_[0-9a-zA-Z]{36}|glpat-[0-9a-zA-Z_-]{20,})"
        ),
    ),
    (
        "connection-string",
        "Database Connection String in Binary",
        Severity.HIGH,
        798,
        re.compile(
            r"(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^\s\"']{10,}",
            re.IGNORECASE,
        ),
    ),
    (
        "private-key-marker",
        "Private Key Material in Binary",
        Severity.CRITICAL,
        321,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "password-assignment",
        "Password Assignment in Binary",
        Severity.HIGH,
        798,
        re.compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*[\"']?[^\s\"']{4,}",
            re.IGNORECASE,
        ),
    ),
]

# Binwalk artifact patterns
_BINWALK_PATTERNS: list[tuple[str, str, Severity, int, re.Pattern[str]]] = [
    (
        "embedded-certificate",
        "Embedded Certificate in Firmware",
        Severity.MEDIUM,
        321,
        re.compile(r"Certificate|X\.509|PEM certificate", re.IGNORECASE),
    ),
    (
        "embedded-private-key",
        "Embedded Private Key in Firmware",
        Severity.CRITICAL,
        321,
        re.compile(r"private key|RSA private", re.IGNORECASE),
    ),
    (
        "embedded-filesystem",
        "Embedded Filesystem in Firmware",
        Severity.LOW,
        200,
        re.compile(
            r"(?:Squashfs|JFFS2|CramFS|UBIFS|ext[234] filesystem|FAT filesystem)",
            re.IGNORECASE,
        ),
    ),
    (
        "debug-symbols",
        "Debug Symbols in Production Binary",
        Severity.LOW,
        489,
        re.compile(r"(?:ELF.*debug|\.debug_info|\.stab|DWARF)", re.IGNORECASE),
    ),
]


def _redact_secret(value: str, keep: int = 4) -> str:
    """Redact a secret value, keeping only the first `keep` characters."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


class StringsIngestor(BaseIngestor):
    """Parses `strings` command output for security-relevant patterns."""

    category = FindingCategory.BINARY

    @property
    def supported_extensions(self) -> list[str]:
        return [".txt", ".strings"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file looks like strings output.

        Heuristic: plain text file with high density of short lines and
        a filename containing 'strings' or having .strings extension.
        """
        if not path.exists():
            return False
        name = path.name.lower()
        if "strings" not in name and path.suffix.lower() != ".strings":
            return False
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:2048]
            lines = head.splitlines()
            return len(lines) >= 5
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse strings output and return findings for security-relevant patterns."""
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise IngestorError(f"Failed to read strings file: {e}") from e

        # Derive binary name from filename (e.g., "firmware.elf.strings" → "firmware.elf")
        binary_name = path.stem if path.suffix == ".strings" else path.name
        binary_name = binary_name.replace(".strings", "").replace("_strings", "")

        # Match patterns and group
        matched: dict[str, list[str]] = {}
        for _line_num, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            for rule_id, _title, _sev, _cwe, pattern in _PATTERNS:
                if pattern.search(line):
                    if rule_id not in matched:
                        matched[rule_id] = []
                    matched[rule_id].append(line)

        findings: list[Finding] = []
        for rule_id, title, severity, cwe_id, _pattern in _PATTERNS:
            if rule_id not in matched:
                continue
            matches = matched[rule_id]
            # Show count and first few redacted examples
            examples = [_redact_secret(m, 20) for m in matches[:3]]
            description = (
                f"{len(matches)} occurrence(s) found in binary '{binary_name}'. "
                f"Examples: {'; '.join(examples)}"
            )
            findings.append(
                Finding(
                    id=f"strings-{slugify(rule_id)}",
                    title=f"{title} ({binary_name})",
                    severity=severity,
                    cwe_id=cwe_id,
                    description=description,
                    impact=("Hardcoded sensitive data in binaries can be extracted by attackers."),
                    remediation=(
                        "Remove sensitive data from binaries. "
                        "Use runtime configuration for secrets."
                    ),
                    affected_hosts=[binary_name],
                    source_code_refs=[SourceCodeRef(file_path=str(path))],
                    source_tool="strings",
                    raw_ref=rule_id,
                )
            )
        return findings


class BinwalkIngestor(BaseIngestor):
    """Parses binwalk analysis output."""

    category = FindingCategory.BINARY

    @property
    def supported_extensions(self) -> list[str]:
        return [".txt", ".json", ".binwalk"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file looks like binwalk output."""
        if not path.exists():
            return False
        name = path.name.lower()
        if path.suffix == ".binwalk":
            return True
        if "binwalk" not in name:
            return False
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:2048]
            # binwalk text output has "DECIMAL" header or JSON array
            return "DECIMAL" in head or "HEXADECIMAL" in head or head.strip().startswith("[")
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse binwalk output and return findings for embedded artifacts."""
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise IngestorError(f"Failed to read binwalk file: {e}") from e

        binary_name = path.stem.replace("_binwalk", "").replace(".binwalk", "")

        # Try JSON format first
        lines_to_scan: list[str] = []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        desc = entry.get("description", "")
                        if desc:
                            lines_to_scan.append(desc)
        except (json.JSONDecodeError, TypeError):
            # Fall back to text format
            lines_to_scan = text.splitlines()

        matched: dict[str, list[str]] = {}
        for line in lines_to_scan:
            line = line.strip()
            if not line:
                continue
            for rule_id, _title, _sev, _cwe, pattern in _BINWALK_PATTERNS:
                if pattern.search(line):
                    if rule_id not in matched:
                        matched[rule_id] = []
                    matched[rule_id].append(line)

        findings: list[Finding] = []
        for rule_id, title, severity, cwe_id, _pattern in _BINWALK_PATTERNS:
            if rule_id not in matched:
                continue
            matches = matched[rule_id]
            description = (
                f"{len(matches)} occurrence(s) in firmware '{binary_name}'. "
                f"Example: {matches[0][:100]}"
            )
            findings.append(
                Finding(
                    id=f"binwalk-{slugify(rule_id)}",
                    title=f"{title} ({binary_name})",
                    severity=severity,
                    cwe_id=cwe_id,
                    description=description,
                    impact=(
                        "Embedded sensitive artifacts in firmware can be extracted by attackers."
                    ),
                    remediation=(
                        "Remove development artifacts and sensitive data "
                        "from production firmware images."
                    ),
                    affected_hosts=[binary_name],
                    source_code_refs=[SourceCodeRef(file_path=str(path))],
                    source_tool="binwalk",
                    raw_ref=rule_id,
                )
            )
        return findings
