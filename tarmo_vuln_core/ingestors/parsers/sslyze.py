"""SSLyze JSON ingestor for pentest-scribe.

Parses SSLyze's --json_out output (sslyze 5.x / 6.x JSON schema) and generates
individual findings for each TLS/SSL weakness found across all scanned servers.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, Severity

logger = logging.getLogger(__name__)

# Mapping: SSLyze scan command key → (finding_id, severity)
# Only entries where the result indicates a weakness are emitted.
_CIPHER_SUITE_CHECKS: dict[str, tuple[str, Severity]] = {
    "ssl_2_0_cipher_suites": ("ssl-v2-enabled", Severity.CRITICAL),
    "ssl_3_0_cipher_suites": ("ssl-v3-enabled", Severity.HIGH),
    "tls_1_0_cipher_suites": ("tls-1-0-enabled", Severity.MEDIUM),
    "tls_1_1_cipher_suites": ("tls-1-1-enabled", Severity.MEDIUM),
}

_VULN_CHECKS: list[tuple[str, str, str, Severity]] = [
    # (scan_command_key, result_field, finding_id, severity)
    ("heartbleed", "is_vulnerable_to_heartbleed", "openssl-heartbleed", Severity.CRITICAL),
    (
        "openssl_ccs_injection",
        "is_vulnerable_to_ccs_injection",
        "openssl-ccs-injection",
        Severity.HIGH,
    ),
]

_PLACEHOLDER_DESC = "See library entry for details."


class SslyzeIngestor(BaseIngestor):
    """Ingestor for SSLyze JSON output (``sslyze --json_out result.json``).

    Generates one finding per vulnerability type, merging all affected servers
    into the ``affected_hosts`` list. The library matcher will enrich description,
    CVSS, CWE, and remediation from the built-in finding library.
    """

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True for JSON files containing an SSLyze ``server_scan_results`` key."""
        if path.suffix.lower() != ".json":
            return False
        try:
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
            return isinstance(data, dict) and "server_scan_results" in data
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse an SSLyze JSON file and return normalized Finding objects.

        Args:
            path: Path to the SSLyze JSON output file.

        Returns:
            List of Finding objects, one per vulnerability type found.

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        try:
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise IngestorError(f"Cannot parse SSLyze JSON {path}: {exc}") from exc

        if "server_scan_results" not in data:
            raise IngestorError(f"Not a valid SSLyze output file: {path}")

        # Accumulate affected hosts per finding id
        # { finding_id: {"hosts": [...], "severity": Severity} }
        findings_map: dict[str, dict] = {}

        for server_result in data["server_scan_results"]:
            if server_result.get("scan_status") != "COMPLETED":
                continue

            server_loc = server_result.get("server_location", {})
            hostname = server_loc.get("hostname", "unknown")
            port = server_loc.get("port", 443)
            host_str = f"{hostname}:{port}"

            scan_result = server_result.get("scan_result") or {}

            # --- Deprecated protocol checks ---
            for cmd_key, (finding_id, severity) in _CIPHER_SUITE_CHECKS.items():
                cmd = scan_result.get(cmd_key) or {}
                if cmd.get("status") != "COMPLETED":
                    continue
                result = cmd.get("result") or {}
                if result.get("is_tls_version_supported"):
                    entry = findings_map.setdefault(finding_id, {"hosts": [], "severity": severity})
                    if host_str not in entry["hosts"]:
                        entry["hosts"].append(host_str)

            # --- Boolean vulnerability checks ---
            for cmd_key, result_field, finding_id, severity in _VULN_CHECKS:
                cmd = scan_result.get(cmd_key) or {}
                if cmd.get("status") != "COMPLETED":
                    continue
                result = cmd.get("result") or {}
                if result.get(result_field):
                    entry = findings_map.setdefault(finding_id, {"hosts": [], "severity": severity})
                    if host_str not in entry["hosts"]:
                        entry["hosts"].append(host_str)

            # --- ROBOT attack ---
            robot_cmd = scan_result.get("robot") or {}
            if robot_cmd.get("status") == "COMPLETED":
                robot_result = (robot_cmd.get("result") or {}).get("robot_result", "")
                if robot_result and "VULNERABLE" in robot_result:
                    finding_id = "tls-robot-attack"
                    entry = findings_map.setdefault(
                        finding_id, {"hosts": [], "severity": Severity.HIGH}
                    )
                    if host_str not in entry["hosts"]:
                        entry["hosts"].append(host_str)

            # --- TLS compression (CRIME) ---
            compress_cmd = scan_result.get("tls_compression") or {}
            if compress_cmd.get("status") == "COMPLETED":
                compress_result = compress_cmd.get("result") or {}
                if compress_result.get("supports_compression"):
                    finding_id = "tls-crime-compression"
                    entry = findings_map.setdefault(
                        finding_id, {"hosts": [], "severity": Severity.MEDIUM}
                    )
                    if host_str not in entry["hosts"]:
                        entry["hosts"].append(host_str)

            # --- Session renegotiation DoS ---
            reneg_cmd = scan_result.get("session_renegotiation") or {}
            if reneg_cmd.get("status") == "COMPLETED":
                reneg_result = reneg_cmd.get("result") or {}
                if reneg_result.get("is_vulnerable_to_client_renegotiation_dos"):
                    finding_id = "tls-renegotiation-dos"
                    entry = findings_map.setdefault(
                        finding_id, {"hosts": [], "severity": Severity.MEDIUM}
                    )
                    if host_str not in entry["hosts"]:
                        entry["hosts"].append(host_str)

        findings: list[Finding] = []
        for finding_id, info in findings_map.items():
            findings.append(
                Finding(
                    id=finding_id,
                    title=finding_id.replace("-", " ").title(),
                    severity=info["severity"],
                    affected_hosts=info["hosts"],
                    description=_PLACEHOLDER_DESC,
                    impact=_PLACEHOLDER_DESC,
                    remediation=_PLACEHOLDER_DESC,
                    source_tool="sslyze",
                    raw_ref=None,
                )
            )

        return findings
