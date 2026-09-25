"""Bandit JSON ingestor."""

from __future__ import annotations

import json
from os.path import basename
from pathlib import Path

from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.models import Finding, FindingCategory, Severity, SourceCodeRef
from tarmo_vuln_core.utils import slugify

_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_DEFAULT_IMPACT = "The vulnerability may allow an attacker to compromise the affected system."
_DEFAULT_REMEDIATION = "Review and remediate the identified issue."

# Curated mapping of Bandit test IDs to CWE numbers.
# Source: https://bandit.readthedocs.io/en/latest/plugins/
_BANDIT_CWE_MAP: dict[str, int] = {
    "B101": 703,  # assert_used → CWE-703 (Improper Check or Handling of Exceptional Conditions)
    "B102": 78,  # exec_used → CWE-78 (OS Command Injection)
    "B103": 732,  # set_bad_file_permissions → CWE-732 (Incorrect Permission Assignment)
    "B104": 1327,  # hardcoded_bind_all_interfaces → CWE-1327 (Binding to All Interfaces)
    "B105": 259,  # hardcoded_password_string → CWE-259 (Hard-coded Password)
    "B106": 259,  # hardcoded_password_funcarg → CWE-259
    "B107": 259,  # hardcoded_password_default → CWE-259
    "B108": 377,  # hardcoded_tmp_directory → CWE-377 (Insecure Temporary File)
    "B110": 390,  # try_except_pass → CWE-390 (Detection of Error Condition Without Action)
    "B112": 390,  # try_except_continue → CWE-390
    "B201": 94,  # flask_debug_true → CWE-94 (Code Injection)
    "B301": 502,  # pickle → CWE-502 (Deserialization of Untrusted Data)
    "B302": 502,  # marshal → CWE-502
    "B303": 328,  # md5/sha1 → CWE-328 (Use of Weak Hash)
    "B304": 327,  # ciphers → CWE-327 (Use of Broken Crypto Algorithm)
    "B305": 327,  # cipher_modes → CWE-327
    "B306": 377,  # mktemp_q → CWE-377
    "B307": 78,  # eval → CWE-78 (OS Command Injection)
    "B308": 94,  # mark_safe → CWE-94 (Code Injection)
    "B310": 918,  # urllib_urlopen → CWE-918 (SSRF)
    "B311": 330,  # random → CWE-330 (Use of Insufficiently Random Values)
    "B312": 295,  # telnetlib → CWE-295 (Improper Certificate Validation)
    "B313": 611,  # xml_bad_cElementTree → CWE-611 (XXE)
    "B314": 611,  # xml_bad_ElementTree → CWE-611
    "B315": 611,  # xml_bad_expatreader → CWE-611
    "B316": 611,  # xml_bad_expatbuilder → CWE-611
    "B317": 611,  # xml_bad_sax → CWE-611
    "B318": 611,  # xml_bad_minidom → CWE-611
    "B319": 611,  # xml_bad_pulldom → CWE-611
    "B320": 611,  # xml_bad_etree → CWE-611
    "B321": 319,  # ftp_related → CWE-319 (Cleartext Transmission)
    "B322": 78,  # input → CWE-78 (OS Command Injection)
    "B323": 295,  # unverified_context → CWE-295
    "B324": 328,  # hashlib_new_insecure → CWE-328
    "B325": 377,  # tempnam → CWE-377
    "B401": 295,  # import_telnetlib → CWE-295
    "B402": 319,  # import_ftplib → CWE-319
    "B403": 502,  # import_pickle → CWE-502
    "B404": 78,  # import_subprocess → CWE-78
    "B405": 611,  # import_xml_etree → CWE-611
    "B406": 611,  # import_xml_sax → CWE-611
    "B407": 611,  # import_xml_expatreader → CWE-611
    "B408": 611,  # import_xml_minidom → CWE-611
    "B409": 611,  # import_xml_pulldom → CWE-611
    "B410": 611,  # import_lxml → CWE-611
    "B411": 502,  # import_xmlrpclib → CWE-502
    "B412": 295,  # import_httpoxy → CWE-295
    "B413": 327,  # import_pycrypto → CWE-327
    "B501": 295,  # request_with_no_cert_validation → CWE-295
    "B502": 295,  # ssl_with_bad_version → CWE-295
    "B503": 295,  # ssl_with_bad_defaults → CWE-295
    "B504": 295,  # ssl_with_no_version → CWE-295
    "B505": 327,  # weak_cryptographic_key → CWE-327
    "B506": 295,  # yaml_load → CWE-295
    "B507": 295,  # ssh_no_host_key_verification → CWE-295
    "B601": 78,  # paramiko_calls → CWE-78
    "B602": 78,  # subprocess_popen_with_shell_equals_true → CWE-78
    "B603": 78,  # subprocess_without_shell_equals_true → CWE-78
    "B604": 78,  # any_other_function_with_shell_equals_true → CWE-78
    "B605": 78,  # start_process_with_a_shell → CWE-78
    "B606": 78,  # start_process_with_no_shell → CWE-78
    "B607": 78,  # start_process_with_partial_path → CWE-78
    "B608": 89,  # hardcoded_sql_expressions → CWE-89 (SQL Injection)
    "B609": 78,  # linux_commands_wildcard_injection → CWE-78
    "B610": 78,  # django_extra_used → CWE-78
    "B611": 89,  # django_rawsql_used → CWE-89
    "B701": 94,  # jinja2_autoescape_false → CWE-94
    "B702": 79,  # use_of_mako_templates → CWE-79 (XSS)
    "B703": 79,  # django_mark_safe → CWE-79
}


class BanditIngestor(BaseIngestor):
    """Parses Bandit JSON output files."""

    category = FindingCategory.SAST

    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def can_handle(self, path: Path) -> bool:
        """Return True if the file is a Bandit JSON report."""
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return False
            if "results" not in data or "generated_at" not in data:
                return False
            results = data["results"]
            if not isinstance(results, list) or not results:
                return False
            first = results[0]
            return "test_id" in first and "issue_severity" in first
        except Exception:
            return False

    def ingest(self, path: Path) -> list[Finding]:
        """Parse a Bandit JSON file and return a list of Finding objects."""
        if not path.exists():
            raise IngestorError(f"File not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IngestorError(f"Failed to parse Bandit JSON: {e}") from e

        findings: list[Finding] = []

        for result in data.get("results", []):
            test_id = result.get("test_id", "")
            test_name = result.get("test_name", "unknown")
            issue_severity = result.get("issue_severity", "MEDIUM").upper()
            issue_text = result.get("issue_text", "")
            filename = result.get("filename", "")
            line_number = result.get("line_number", 0)

            severity = _SEVERITY_MAP.get(issue_severity, Severity.MEDIUM)

            finding_id = f"bandit-{test_id.lower()}-{slugify(basename(filename))}-l{line_number}"

            # Bandit JSON emits start only: line_number; it does not carry
            # end_line or column offsets in any released format. Leave them
            # None rather than stuffing col_offset into end_line.
            source_ref = SourceCodeRef(
                file_path=filename,
                start_line=line_number if line_number else None,
                snippet=result.get("code", "").strip(),
            )

            cwe_id = _BANDIT_CWE_MAP.get(test_id)

            findings.append(
                Finding(
                    id=finding_id,
                    title=test_name,
                    severity=severity,
                    description=issue_text,
                    impact=_DEFAULT_IMPACT,
                    remediation=_DEFAULT_REMEDIATION,
                    cwe_id=cwe_id,
                    affected_hosts=[filename],
                    source_code_refs=[source_ref],
                    source_tool="bandit",
                    raw_ref=test_id,
                )
            )

        return findings
