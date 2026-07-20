# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| older   | No        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's built-in advisory system:

**[Report a security vulnerability](https://github.com/Tarmo-Technologies/tarmo-vuln-core/security/advisories/new)**

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce (including a minimal sample input file if relevant)
- The version of tarmo-vuln-core affected
- Any suggested mitigations

### Response SLAs

| Severity | Initial response | Fix target |
|----------|-----------------|------------|
| Critical | 72 hours        | 14 days    |
| High     | 72 hours        | 30 days    |
| Medium   | 7 days          | 90 days    |
| Low      | 14 days         | Next minor |

## Scope

### In scope (HIGH severity)

- **XML parsing** — XXE / billion-laughs entity expansion via malicious scanner reports (Nmap, Nessus, Burp, ZAP, Qualys, etc.). All XML parsing uses `defusedxml`; any bypass is a critical issue.
- **Path traversal** — a parser or signer writing or reading outside an expected directory based on attacker-controlled input file contents.
- **Memory safety in the Rust extension** — any panic-free path that leads to unsound behaviour in the `vuln_core_rs` dedup/correlation code.
- **Dependency vulnerabilities** — CVEs in pinned dependencies that affect the library's attack surface.

### By design (not vulnerabilities)

- **Custom ingestor plugin execution** — registering a plugin executes arbitrary code. This is the documented extension mechanism; trust your plugin sources.
- **LLM enrichment content** — the optional enrichment step sends finding text to a configured LLM endpoint. The caller controls the endpoint and API key.
