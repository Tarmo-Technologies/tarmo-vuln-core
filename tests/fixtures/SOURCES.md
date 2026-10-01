# Fixture Sources

Provenance for real-world scanner output files in `tests/fixtures/`.
These fixtures are used by structural validation tests and, after C5, by parser integration tests.

| Fixture | Source |
|---------|--------|
| `nmap_real.xml` | [mozilla/minion-nmap-plugin](https://raw.githubusercontent.com/mozilla/minion-nmap-plugin/master/etc/sample-nmap-output.xml) |
| `nessus_real.nessus` | [DanMcInerney/msf-autoshell](https://raw.githubusercontent.com/DanMcInerney/msf-autoshell/master/example-scan1.nessus) |
| `burp_real.xml` | [hvqzao/report-ng](https://raw.githubusercontent.com/hvqzao/report-ng/master/examples/example-2C-scan-export-Burp.xml) |
| `metasploit_real.xml` | No public URL; authentic MSF lab export via pentest-scribe |
| `zap_real.xml` | [archerysec/report-sample](https://raw.githubusercontent.com/archerysec/report-sample/main/OWASP-ZAP/OWASP-ZAP-v2.7.0.xml) |
| `acunetix_real.xml` | [DefectDojo/django-DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/unittests/scans/acunetix/many_findings.xml) |
| `nikto_real.xml` | [DefectDojo/django-DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/unittests/scans/nikto/nikto-output.xml) |
| `nexpose_real.xml` | [DefectDojo/django-DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/unittests/scans/nexpose/many_vulns.xml) |
| `openvas_real.xml` | [archerysec/report-sample](https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml) |
| `qualys_real.xml` | [DefectDojo/django-DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/unittests/scans/qualys/Qualys_Sample_Report.xml) |
| `sarif_real.json` | [microsoft/sarif-tutorials](https://raw.githubusercontent.com/microsoft/sarif-tutorials/main/samples/1-Introduction/simple-example.sarif) |
| `sslyze_real.json` | [nabla-c0d3/sslyze](https://raw.githubusercontent.com/nabla-c0d3/sslyze/release/tests/json_tests/sslyze_output.json) |
| `trivy_real.json` | [aquasecurity/trivy](https://raw.githubusercontent.com/aquasecurity/trivy/main/integration/testdata/debian-buster.json.golden) |
| `wpscan_real.json` | [dradis/dradis-wpscan](https://raw.githubusercontent.com/dradis/dradis-wpscan/main/spec/fixtures/files/sample.json) |
| `bandit_real.json` | [AppThreat/sast-scan](https://raw.githubusercontent.com/AppThreat/sast-scan/master/test/data/bandit-report.json) |
| `semgrep_real.sarif` | [j3ssie/sample-semgrep-ci](https://raw.githubusercontent.com/j3ssie/sample-semgrep-ci/main/semgrep-results.sarif) |
| `cppcheck_real.xml` | [SonarOpenCommunity/sonar-cxx](https://raw.githubusercontent.com/SonarOpenCommunity/sonar-cxx/master/integration-tests/testdata/smoketest_project/build/cppcheck-report.xml) |
| `flawfinder_real.csv` | [david-a-wheeler/flawfinder](https://raw.githubusercontent.com/david-a-wheeler/flawfinder/master/test/correct-results.csv) |

Sample fixtures (`*_sample.*`) were hand-crafted for pentest-scribe unit tests and have no external provenance.

Additional realistic SAST parser fixtures used for schema hardening:

| Fixture | Source |
|---------|--------|
| `coverity_cli_sample.json` | Adapted from [DefectDojo/django-DefectDojo `unittests/scans/coverity_scan/one_vuln.json`](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/2f25c4510361e2f27f63fbbcff3901cbd2ef4a07/unittests/scans/coverity_scan/one_vuln.json) |
| `fortify_realistic_sample.fvdl` | Trimmed from [DefectDojo/django-DefectDojo `unittests/scans/fortify/audit.fvdl`](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/2f25c4510361e2f27f63fbbcff3901cbd2ef4a07/unittests/scans/fortify/audit.fvdl) |
| `coverity_generated_v10.json` | Built on the `coverity_cli_sample.json` (formatVersion 10) issue/event schema: an `OVERRUN` in build-generated `build/gen/foo_idl.c` reported with `cov-format-errors --strip-path /home/ci/work/` (stripped + unstripped paths, `functionDisplayName`, one event without `strippedFilePathname`) plus an in-source `RESOURCE_LEAK`. |
| `coverity_generated_v7.json` | Same defect in formatVersion 7 layout without `--strip-path`: the stripped fields repeat the volatile absolute build root `/tmp/ci-7f3e2a/`, and regeneration shifted the line. |
| `sarif_build_roots.sarif` | CodeQL-style SARIF 2.1.0 run exercising `originalUriBaseIds` (`%SRCROOT%` absolute, `BUILDROOT` chained under it, out-of-tree `OBJROOT`, `SYSINCLUDE` with no `uri`), `file:///` URIs (percent-encoded, in and out of the source root), `run.artifacts` roles (`uncontrolled`) and a `generated` tag, and an index-only `artifactLocation`. |
| `cppcheck_valueflow/cppcheck.xml` | Real `cppcheck 2.13.0` output, generated 2026-10-01 by running `cppcheck --xml --enable=warning src/ 2> cppcheck.xml` in `cppcheck_valueflow/` over the two C files in `cppcheck_valueflow/src/` (written for this fixture). It has multi-location value-flow errors (`nullPointer`, `arrayIndexOutOfBoundsCond`, `nullPointerRedundantCheck`, `ctunullpointer`) and one single-location error (`uninitvar`). The text run of the same sources (`--template='{file}:{line}:{column}: {id}: {message}'`) reports each error at its first XML `<location>`, matching the cppcheck manual ("The primary location is listed first") and `ErrorMessage::toXML` (`lib/errorlogger.cpp`, which writes the call stack in reverse). |
| `codeql_path_problem.sarif` | Trimmed from [DefectDojo/django-DefectDojo `unittests/scans/sarif/codeQL-output.sarif`](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/5791c7445ea64625b738aeb1bb776798bb812de1/unittests/scans/sarif/codeQL-output.sarif) (BSD-3-Clause; the embedded code snippets are from the MIT-licensed fportantier/vulpy). Real CodeQL 2.5.4 output for a Python project with path-problem `codeFlows`. Kept: results 2 (`py/empty-except`, no `codeFlows`), 56 (`py/path-injection`, 2 `codeFlows`, one step without a region) and 57 (`py/reflective-xss`, 7 `codeFlows`) unchanged; the driver's rules reduced to those three with `ruleIndex` renumbered to match; `tool.extensions` and the other 69 results dropped; `artifacts`, `columnKind` and `properties` kept as is. Re-serialized with 2-space indentation. |

BHF (Build Harness Fuzz) output:

| Fixture | Source |
|---------|--------|
| `bhf/auto-run/` | Real `bhf auto` work directory (BHF 0.2.32) from a small C target, with paths sanitized: scanned source root `/work/src`, BHF work dir `/work/bhf`, BHF runtime `/opt/bhf`. `decoded.json` files were dropped (unused). |
| `bhf/static/` | Real `bhf static` output (SARIF and native `bhf.static.v1` JSON) for the same target. |
