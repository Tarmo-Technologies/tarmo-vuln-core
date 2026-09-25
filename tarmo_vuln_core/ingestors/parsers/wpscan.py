"""WPScan WordPress vulnerability scanner JSON output ingestor."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity

_WPSCAN_DEFAULT_IMPACT = (
    "Successful exploitation may allow an attacker to compromise the WordPress "
    "installation, its data, or the underlying server."
)
_WPSCAN_DEFAULT_REMEDIATION = (
    "Update the affected WordPress core, plugin, or theme to the latest version. "
    "Remove unused plugins and themes. Follow WordPress hardening guidelines."
)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _normalize_cve(raw: str) -> str:
    """Ensure a CVE string has the 'CVE-' prefix."""
    raw = raw.strip()
    if raw.upper().startswith("CVE-"):
        return raw.upper()
    # Raw format from older WPScan: "2017-6814" → "CVE-2017-6814"
    if re.match(r"^\d{4}-\d+$", raw):
        return f"CVE-{raw}"
    return raw.upper()


def _vuln_severity(vuln: dict[str, Any]) -> Severity:
    """Infer severity from a WPScan vulnerability dict."""
    raw = (vuln.get("severity") or "").lower()
    if raw in _SEVERITY_MAP:
        return _SEVERITY_MAP[raw]
    # Fallback: infer from title keywords
    title = (vuln.get("title") or "").lower()
    if re.search(r"remote code execution|rce\b|sql injection|critical", title):
        return Severity.CRITICAL
    if re.search(r"privilege escalation|arbitrary file|upload|auth bypass", title):
        return Severity.HIGH
    if re.search(r"cross.site scripting|xss\b|csrf|open redirect|ssrf", title):
        return Severity.MEDIUM
    if re.search(r"information disclosure|exposure|enumeration|brute", title):
        return Severity.LOW
    return Severity.MEDIUM


def _vuln_to_finding(
    vuln: dict[str, Any],
    source_label: str,
    host: str,
) -> Finding | None:
    """Convert a single WPScan vulnerability entry to a Finding, or None if no title."""
    title = (vuln.get("title") or "").strip()
    if not title:
        return None

    refs = vuln.get("references") or {}
    cve_list: list[str] = [_normalize_cve(c) for c in (refs.get("cve") or [])]
    raw_ref = cve_list[0] if cve_list else None

    # Build slug: prefer first CVE, fall back to title slug
    if raw_ref:
        slug = f"wpscan-{raw_ref.lower().replace('cve-', 'cve-')}"
    else:
        slug_base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        slug = f"wpscan-{slug_base[:60]}"

    fixed_in = vuln.get("fixed_in") or ""
    desc_parts = [title]
    if fixed_in:
        desc_parts.append(f"Fixed in version: {fixed_in}")
    if cve_list:
        desc_parts.append("CVEs: " + ", ".join(cve_list))
    description = "\n".join(desc_parts)

    return Finding(
        id=slug,
        title=title,
        severity=_vuln_severity(vuln),
        description=description,
        impact=_WPSCAN_DEFAULT_IMPACT,
        remediation=_WPSCAN_DEFAULT_REMEDIATION,
        cvss_score=None,
        cvss_vector=None,
        cwe_id=None,
        owasp_id=None,
        affected_hosts=[host] if host else [],
        source_tool="wpscan",
        raw_ref=raw_ref,
    )


class WpscanIngestor(BaseIngestor):
    """Parses WPScan JSON output files (``wpscan --format json``)."""

    category = FindingCategory.DAST

    @property
    def supported_extensions(self) -> list[str]:
        """File extensions this ingestor handles."""
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a WPScan JSON output.

        Checks for a ``target_url`` key plus at least one of ``version``,
        ``wordpress_version``, ``plugins``, or ``themes``.
        """
        if not path.exists():
            return False
        if path.suffix.lower() not in {".json"}:
            return False
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return False
        if not isinstance(data, dict):
            return False
        if "target_url" not in data:
            return False
        return any(k in data for k in ("version", "wordpress_version", "plugins", "themes"))

    def ingest(self, path: Path) -> list[Finding]:
        """Parse WPScan JSON and return normalised findings.

        Processes:
        - Core WordPress version vulnerabilities
        - Plugin vulnerabilities
        - Theme vulnerabilities
        - Synthetic findings: outdated core, XML-RPC enabled, readme exposed,
          user enumeration

        Deduplicates findings by slug (same CVE across sections = one finding).

        Args:
            path: Path to a WPScan JSON output file.

        Returns:
            List of Finding objects.

        Raises:
            IngestorError: If the file cannot be read or parsed.
        """
        if not path.exists():
            raise IngestorError(f"File not found: {path}")
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                data: dict[str, Any] = json.load(fh)
        except json.JSONDecodeError as exc:
            raise IngestorError(f"Failed to parse WPScan JSON: {exc}") from exc
        except OSError as exc:
            raise IngestorError(f"Cannot read file: {exc}") from exc

        if not isinstance(data, dict):
            raise IngestorError("WPScan JSON root must be an object")

        target_url: str = data.get("target_url") or data.get("effective_url") or ""
        target_ip: str = data.get("target_ip") or ""
        host = target_url.rstrip("/") or target_ip or ""

        # slug → Finding (dedup map)
        findings_map: dict[str, Finding] = {}

        def _add(f: Finding | None) -> None:
            if f is None:
                return
            if f.id not in findings_map:
                findings_map[f.id] = f
            else:
                # Merge hosts
                existing = findings_map[f.id]
                merged_hosts = list(dict.fromkeys(existing.affected_hosts + f.affected_hosts))
                findings_map[f.id] = existing.model_copy(update={"affected_hosts": merged_hosts})

        # ── Core WordPress version ──────────────────────────────────────────
        wp_ver: dict = data.get("wordpress_version") or data.get("version") or {}
        if isinstance(wp_ver, dict):
            ver_status = (wp_ver.get("status") or "").lower()
            ver_number = wp_ver.get("number") or ""
            if ver_status in ("outdated", "insecure") or (
                ver_status and ver_status not in ("latest", "")
            ):
                desc = f"WordPress {ver_number} is {ver_status}."
                if ver_number:
                    desc += " Update to the latest stable release."
                _add(
                    Finding(
                        id="wordpress-outdated-core",
                        title=f"WordPress Core {ver_number} ({ver_status.title()})",
                        severity=Severity.MEDIUM,
                        description=desc,
                        impact=(
                            "An outdated WordPress core may contain known vulnerabilities "
                            "that can be exploited to compromise the site."
                        ),
                        remediation=(
                            "Update WordPress core to the latest stable release via the "
                            "WordPress Dashboard or WP-CLI: `wp core update`."
                        ),
                        cvss_score=None,
                        cvss_vector=None,
                        cwe_id=None,
                        owasp_id="A06:2021",
                        affected_hosts=[host] if host else [],
                        source_tool="wpscan",
                        raw_ref=None,
                    )
                )
            for vuln in wp_ver.get("vulnerabilities") or []:
                _add(_vuln_to_finding(vuln, "wordpress_core", host))

        # ── Plugins ─────────────────────────────────────────────────────────
        plugins: dict = data.get("plugins") or {}
        if isinstance(plugins, dict):
            for _slug, plugin_info in plugins.items():
                if not isinstance(plugin_info, dict):
                    continue
                for vuln in plugin_info.get("vulnerabilities") or []:
                    _add(_vuln_to_finding(vuln, f"plugin:{_slug}", host))

        # ── Themes ──────────────────────────────────────────────────────────
        themes: dict = data.get("themes") or {}
        if isinstance(themes, dict):
            for _slug, theme_info in themes.items():
                if not isinstance(theme_info, dict):
                    continue
                for vuln in theme_info.get("vulnerabilities") or []:
                    _add(_vuln_to_finding(vuln, f"theme:{_slug}", host))

        # main_theme (older WPScan format)
        main_theme: dict = data.get("main_theme") or {}
        if isinstance(main_theme, dict):
            t_slug = main_theme.get("slug") or "main_theme"
            for vuln in main_theme.get("vulnerabilities") or []:
                _add(_vuln_to_finding(vuln, f"theme:{t_slug}", host))

        # ── Interesting findings (synthetic) ────────────────────────────────
        for finding in data.get("interesting_findings") or []:
            if not isinstance(finding, dict):
                continue
            ftype = (finding.get("type") or "").lower()

            if ftype == "xmlrpc":
                _add(
                    Finding(
                        id="wordpress-xmlrpc-enabled",
                        title="WordPress XML-RPC Enabled",
                        severity=Severity.MEDIUM,
                        description=(
                            "The XML-RPC interface (xmlrpc.php) is enabled. "
                            "It can be abused for brute-force amplification attacks "
                            "and is a common target for Metasploit modules."
                        ),
                        impact=(
                            "Attackers can perform brute-force login attacks via "
                            "system.multicall (1000 passwords per request), exploit "
                            "known XML-RPC vulnerabilities, or use it as a pivot point."
                        ),
                        remediation=(
                            "Disable XML-RPC by adding a filter in your theme's "
                            "functions.php: `add_filter('xmlrpc_enabled', '__return_false')`. "
                            "Alternatively, block access via the web server config."
                        ),
                        cvss_score=None,
                        cvss_vector=None,
                        cwe_id=None,
                        owasp_id="A05:2021",
                        affected_hosts=[host] if host else [],
                        source_tool="wpscan",
                        raw_ref=None,
                    )
                )
            elif ftype == "readme":
                _add(
                    Finding(
                        id="wordpress-readme-exposed",
                        title="WordPress readme.html Accessible",
                        severity=Severity.INFO,
                        description=(
                            "The WordPress readme.html file is accessible. "
                            "It discloses the WordPress version and installation details."
                        ),
                        impact=(
                            "Version disclosure from readme.html assists attackers in "
                            "targeting known CVEs for the installed WordPress version."
                        ),
                        remediation=(
                            "Delete or restrict access to readme.html, license.txt, "
                            "and wp-config-sample.php on the production server."
                        ),
                        cvss_score=None,
                        cvss_vector=None,
                        cwe_id=None,
                        owasp_id="A05:2021",
                        affected_hosts=[host] if host else [],
                        source_tool="wpscan",
                        raw_ref=None,
                    )
                )

        # ── User enumeration ─────────────────────────────────────────────────
        users = data.get("users") or {}
        # users can be a dict {username: {...}} or a list [{username:...}]
        has_users = (isinstance(users, dict) and bool(users)) or (
            isinstance(users, list) and bool(users)
        )
        if has_users:
            if isinstance(users, dict):
                usernames = list(users.keys())
            else:
                usernames = [u.get("username", "") for u in users if isinstance(u, dict)]
            usernames = [u for u in usernames if u]
            _add(
                Finding(
                    id="wordpress-user-enumeration",
                    title="WordPress User Enumeration",
                    severity=Severity.INFO,
                    description=(
                        f"WPScan enumerated {len(usernames)} WordPress user(s): "
                        + ", ".join(usernames[:10])
                        + ("..." if len(usernames) > 10 else "")
                        + ".\nKnown usernames can be used for targeted password attacks."
                    ),
                    impact=(
                        "Knowledge of valid usernames reduces the search space for "
                        "brute-force and credential stuffing attacks against wp-login.php "
                        "and the XML-RPC interface."
                    ),
                    remediation=(
                        "Restrict author archive pages or use a plugin to block user "
                        "enumeration. Enforce strong passwords and lockout policies. "
                        "Consider renaming the default 'admin' user."
                    ),
                    cvss_score=None,
                    cvss_vector=None,
                    cwe_id=None,
                    owasp_id="A07:2021",
                    affected_hosts=[host] if host else [],
                    source_tool="wpscan",
                    raw_ref=None,
                )
            )

        return list(findings_map.values())
