"""Configuration file security analyzer.

This is a direct analysis tool, not a parser for another tool's output.
It scans common configuration file formats for security issues.
"""

from __future__ import annotations

import re
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

# Extensions that only a config analyzer would handle (no other ingestor claims these)
_EXCLUSIVE_CONFIG_EXTENSIONS = frozenset([".env", ".ini", ".conf", ".properties", ".toml", ".cfg"])

# All config extensions including those shared with other ingestors
_ALL_CONFIG_EXTENSIONS = _EXCLUSIVE_CONFIG_EXTENSIONS | frozenset(
    [".yaml", ".yml", ".json", ".xml"]
)

# Comment patterns per format
_COMMENT_PATTERNS = [
    re.compile(r"^\s*#"),  # Shell, YAML, TOML, Properties, .env
    re.compile(r"^\s*//"),  # JSON (informal), C-style
    re.compile(r"^\s*;"),  # INI
    re.compile(r"^\s*<!--"),  # XML
]


def _is_comment(line: str) -> bool:
    """Return True if the line is a comment."""
    return any(p.match(line) for p in _COMMENT_PATTERNS)


# Detection rules: (id, title, severity, cwe_id, pattern, description)
_RULES: list[tuple[str, str, Severity, int, re.Pattern[str], str]] = [
    (
        "debug-mode-enabled",
        "Debug Mode Enabled",
        Severity.HIGH,
        489,
        re.compile(
            r"""(?ix)
            (?:DEBUG|debug_mode|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)
            \s*[=:]\s*
            (?:true|1|yes|on|enabled)\b
            """,
        ),
        (
            "Debug mode is enabled in configuration, "
            "potentially exposing stack traces and internal state."
        ),
    ),
    (
        "default-password",
        "Default or Weak Password in Configuration",
        Severity.HIGH,
        798,
        re.compile(
            r"""(?ix)
            (?:password|passwd|pass|secret|pwd)
            \s*[=:]\s*['"]?
            (?:password|admin|root|test|123456|changeme|default|guest|letmein|welcome|qwerty)
            ['"]?\s*$
            """,
        ),
        "A default or commonly-known password was found in configuration.",
    ),
    (
        "cleartext-credential",
        "Cleartext Credential in Configuration",
        Severity.HIGH,
        256,
        re.compile(
            r"""(?ix)
            (?:password|passwd|secret|api_key|apikey|token|auth_token|
            access_key|private_key|smtp_pass|db_pass|database_password|
            mysql_password|postgres_password|redis_password)
            \s*[=:]\s*['"]?
            [^\s'"#;]{8,}
            """,
        ),
        (
            "A cleartext credential was found in configuration. "
            "Credentials should be stored in a secrets manager."
        ),
    ),
    (
        "insecure-tls-config",
        "Insecure TLS Configuration",
        Severity.HIGH,
        326,
        re.compile(
            r"""(?ix)
            (?:ssl_version|tls_version|ssl_protocol|protocol)
            \s*[=:]\s*['"]?
            (?:SSLv2|SSLv3|TLSv1\.0|TLSv1$)
            """,
        ),
        (
            "Insecure TLS/SSL protocol version configured. "
            "SSLv2, SSLv3, and TLS 1.0 have known vulnerabilities."
        ),
    ),
    (
        "permissive-cors",
        "Overly Permissive CORS Configuration",
        Severity.MEDIUM,
        942,
        re.compile(
            r"""(?ix)
            (?:cors_origin|access.control.allow.origin|allowed_origins|cors_allowed)
            \s*[=:]\s*['"]?\*['"]?
            """,
        ),
        (
            "CORS is configured to allow all origins (*), "
            "permitting cross-origin requests from any domain."
        ),
    ),
    (
        "dev-url-in-config",
        "Development URL in Configuration",
        Severity.LOW,
        489,
        re.compile(
            r"""(?ix)
            (?:url|host|server|endpoint|base_url|api_url)
            \s*[=:]\s*['"]?
            (?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|
            .*\.local|.*\.dev|.*\.test|.*staging\.)
            """,
        ),
        "A development, staging, or localhost URL was found in configuration.",
    ),
    (
        "verbose-errors",
        "Verbose Error Reporting Enabled",
        Severity.MEDIUM,
        209,
        re.compile(
            r"""(?ix)
            (?:display_errors|show_errors|error_reporting|verbose_errors|
            SHOW_SQL|log_level|LOG_LEVEL)
            \s*[=:]\s*['"]?
            (?:true|1|yes|on|all|E_ALL|DEBUG|TRACE)
            ['"]?\s*$
            """,
        ),
        (
            "Verbose error reporting is enabled, "
            "potentially exposing stack traces and internal state to users."
        ),
    ),
    (
        "exposed-admin-endpoint",
        "Admin or Debug Endpoint Configured",
        Severity.MEDIUM,
        489,
        re.compile(
            r"""(?ix)
            (?:admin_url|debug_url|admin_path|debug_endpoint|
            management_endpoint|actuator_endpoint)
            \s*[=:]\s*['"]?
            [^\s'"#;]+
            """,
        ),
        "An admin or debug endpoint is configured and may be accessible in production.",
    ),
]


class ConfigAnalyzerIngestor(BaseIngestor):
    """Scans configuration files for security issues."""

    @property
    def supported_extensions(self) -> list[str]:
        return list(_ALL_CONFIG_EXTENSIONS)

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a configuration file.

        Only auto-detects on exclusive config extensions (.env, .ini, .conf,
        .properties, .toml, .cfg). Shared extensions (.yaml, .json, .xml) are
        NOT auto-detected to avoid claiming files intended for other ingestors.
        """
        if not path.exists():
            return False
        return path.suffix.lower() in _EXCLUSIVE_CONFIG_EXTENSIONS

    def ingest(self, path: Path) -> list[Finding]:
        """Scan a configuration file for security issues."""
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise IngestorError(f"Failed to read config file: {e}") from e

        lines = text.splitlines()
        # Track which rules matched and their locations
        matched: dict[str, list[SourceCodeRef]] = {}

        for line_num, line in enumerate(lines, start=1):
            if not line.strip() or _is_comment(line):
                continue

            for rule_id, _title, _sev, _cwe, pattern, _desc in _RULES:
                if pattern.search(line):
                    if rule_id not in matched:
                        matched[rule_id] = []
                    matched[rule_id].append(
                        SourceCodeRef(
                            file_path=str(path),
                            start_line=line_num,
                        )
                    )

        findings: list[Finding] = []

        for rule_id, title, severity, cwe_id, _pattern, description in _RULES:
            if rule_id not in matched:
                continue

            refs = matched[rule_id]
            findings.append(
                Finding(
                    id=f"config-{slugify(rule_id)}",
                    title=title,
                    severity=severity,
                    cwe_id=cwe_id,
                    description=description,
                    impact=(
                        "Misconfiguration may expose sensitive data or weaken security controls."
                    ),
                    remediation=(
                        "Review and harden the configuration before deploying to production."
                    ),
                    affected_hosts=[str(path)],
                    source_code_refs=refs,
                    source_tool="config-analyzer",
                    raw_ref=rule_id,
                )
            )

        return findings
