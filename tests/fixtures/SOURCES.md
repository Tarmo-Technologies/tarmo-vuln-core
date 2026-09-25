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

BHF (Build Harness Fuzz) output:

| Fixture | Source |
|---------|--------|
| `bhf/auto-run/` | Real `bhf auto` work directory (BHF 0.2.32) from a small C target, with paths sanitized: scanned source root `/work/src`, BHF work dir `/work/bhf`, BHF runtime `/opt/bhf`. `decoded.json` files were dropped (unused). |
| `bhf/static/` | Real `bhf static` output (SARIF and native `bhf.static.v1` JSON) for the same target. |
