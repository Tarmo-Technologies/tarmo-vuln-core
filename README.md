# tarmo-vuln-core

Shared vulnerability processing library used by [pentest-scribe](https://github.com/Tarmo-Technologies/pentest-scribe) and other Tarmo security tools. Provides normalized models, parsers, deduplication/merge logic, finding enrichment, and a diff engine.

## Features

- **40 built-in parsers** — Nmap, Nessus, Nexpose, Burp Suite, Acunetix, Nikto, OWASP ZAP, OpenVAS, Qualys, Metasploit, Trivy, WPScan, SSLyze, Tenable.io, Semgrep, BloodHound, HackerOne, Bandit, Cppcheck, SARIF 2.1.0, Gitleaks, TruffleHog, config file analyzer, `strings` output, `binwalk` output, CSV, manual YAML, ESLint, Pylint, GNAT SAS, Sigasi, SRM/CodeDx, OWASP Dependency Check, SARP, Checkmarx, Coverity, Fortify, Binary Analyzer, and BHF (fuzz + static); auto-detection and custom plugin support. XML parsing goes through `defusedxml` (entity declarations and external references are refused), and Fortify `.fpr` archives have a decompressed-size cap
- **Deduplication engine** — content-hash dedup (Rust xxHash64 with Python fallback); preserves first-seen order
- **Correlation engine** — cross-tool similarity scoring with 3-tier Rust pipeline (deterministic blocking → MinHash/LSH → weighted scoring); per-severity threshold overrides; Python fallback for portability
- **Finding merge** — same-id re-ingest (new content wins, assessor fields preserved) and cross-tool merge (hosts/instances/tools accumulated, higher CVSS kept)
- **Diff engine** — compare before/after finding sets; categorize as new, resolved, or changed (severity/host regressions)
- **Enrichment** — NVD CVE lookup (disk-cached, rate-limited), LLM-generated prose via any OpenAI-compatible endpoint
- **Finding library** — curated YAML definitions (web, auth, API, network, cloud, SAST, secrets) with matcher supporting Nessus, CVE, CWE, Semgrep, Bandit, Gitleaks, and TruffleHog alias types; completeness checker and import from DefectDojo/Ghostwriter
- **Workflow engine** — configurable status transition graph with 8 finding statuses
- **Report signing** — PAdES-T PDF signatures via pyhanko (RFC 3161 timestamping) and ECDSA detached `.sig` for arbitrary artifacts; ECDSA P-256 keygen helper
- **Host authorization** — shared scope/port primitives (`strip_port`, `address_matches_scope_entry`) consumed by storm and scribe
- **Normalized models** — Pydantic v2 models for Finding, Instance, Evidence, Host, DreadScore, and Severity with full ordinal comparison

## Architecture

tarmo-vuln-core is a hybrid Python + Rust package:

- **`tarmo_vuln_core`** — Pure Python package containing Pydantic models, parsers, and business logic.
- **`vuln_core_rs`** — Compiled Rust extension (via PyO3/maturin) for performance-critical operations.

The two are independently importable. The Python package loads without the Rust extension, so pure-Python usage works without a Rust toolchain.

## Supported Parsers

| Parser | Format | Notes |
|---|---|---|
| Nmap | XML (`-oX`) | Open ports as findings; host inventory extraction |
| Nessus | `.nessus` XML | Groups by plugin ID; library alias matching |
| Nexpose / InsightVM | XML (`NexposeReport`) | Groups by vuln ID; CVSS + CVE extraction |
| Burp Suite | XML | Groups by issue name; Instance objects with host/port/path |
| Acunetix / Invicti | XML (`ScanGroup`) | CVSS3 score/vector; CWE and CVE extraction |
| Nikto | XML | Web server findings; severity from keyword heuristics |
| OWASP ZAP | XML (`OWASPZAPReport`) | Groups by pluginid across sites; CWE extraction |
| OpenVAS / GVM | XML | NVT OID grouping; auto-upgrades HIGH→CRITICAL at CVSS 9.0+ |
| Qualys | XML (`ASSET_DATA_REPORT`) | QID-based grouping; prefers CVSSv3 |
| Metasploit | CSV or XML | Dual-schema support (flat and host-nested) |
| Trivy | JSON | Container/IaC CVEs; CVSS prefers NVD scores |
| WPScan | JSON | WordPress CVEs; synthetic findings for XML-RPC, user enum |
| SSLyze | JSON | TLS weakness checks: deprecated protocols, Heartbleed, ROBOT, CRIME |
| Tenable.io | JSON | Plugin-ID grouping; CVSSv3 + CVE extraction |
| Semgrep | JSON/SARIF | SARIF 2.1.0 subclass; rule-based SAST findings |
| BloodHound CE | JSON | AD attack-path findings; domain-aware impact |
| HackerOne | JSON | Bug bounty reports; CVSS from relationships |
| Bandit | JSON | Python SAST; one finding per result with file/line |
| Cppcheck | XML | C/C++ static analysis; one finding per `<error>`, primary location as the sink ref (file and line; its column only on the flow), other locations in `extra_fields["cppcheck_locations"]` and as `data_flows` steps |
| SARIF 2.1.0 | JSON/SARIF | Generic SARIF import; CWE from relationships; `codeFlows` as `data_flows` |
| Gitleaks | JSON | Secret scanning; groups by RuleID; populates `source_code_refs` |
| TruffleHog | JSON-lines | Secret scanning; verified=CRITICAL; uses only redacted values |
| Config Analyzer | `.env`/`.ini`/`.yaml`/etc. | Direct analyzer; detects debug flags, weak passwords, cleartext creds, insecure TLS |
| `strings` output | `.strings`/`.txt` | Binary analysis; detects URLs, API keys, private keys, connection strings |
| `binwalk` output | `.binwalk`/`.txt` | Firmware analysis; detects embedded certs, keys, filesystems, debug symbols |
| CSV | CSV | Generic import; requires `title` + `severity` columns |
| Manual | YAML/JSON | Full Finding model; `source_tool="manual"` |
| ESLint | JSON | JavaScript/TypeScript SAST findings; CData CWE enrichment |
| Pylint | JSON | Python SAST findings; CData CWE enrichment |
| GNAT SAS | JSON/SARIF | Ada static analysis (GNAT Static Analysis Suite) |
| Sigasi | JSON | VHDL/Verilog diagnostic findings |
| SRM / CodeDx | XML | Cross-scanner deduplication; groups by vuln ID across tools |
| OWASP Dependency Check | JSON | CVE-based dependency vulnerability findings; dedup by CVE |
| SARP | CSV (17-column) | Spreadsheet-based finding import with CData CWE mapping |
| Checkmarx | XML (`CxXMLResults`) | SAST findings; CWE extraction; CData enrichment; each `Path` as a `data_flows` entry |
| Coverity | JSON | C/C++ SAST findings; groups by checker name; `events` as a `data_flows` entry (main event as the sink) |
| Fortify | FPR (ZIP/FVDL XML) | SAST findings; severity from DefaultSeverity float |
| Binary Analyzer | `.strings`/`.binwalk`/`.txt` | Hardcoded secrets, URLs, API keys, and embedded artifacts in binaries |
| BHF (fuzz) | Work dir, `findings.csv`, or `finding.json` | One finding per root-cause row; `Finding.fuzz` carries sanitizer, verdict, project-only stack, and reproducer; paths relative to the scanned source root |
| BHF (static) | `static-report.sarif` / `static-report.json` | SAST findings; enclosing function as `symbol`; verdict/baseline/triage tags |

## Public API

Key exports from `tarmo_vuln_core`:

```python
# Models (top-level re-exports)
Finding, FindingStatus, FindingCategory, Severity, Instance, Evidence, EvidenceType
FuzzEvidence, StackFrame
Host, HostProperty, DreadScore
Protocol, PortState, ServiceName
# Additional models available via tarmo_vuln_core.models:
#   SourceCodeRef, RuntimeTarget
#   FlowStep, DataFlow (Finding.data_flows: scanner source-to-sink paths,
#   at most 3 flows of at most 32 steps; never source_code_refs)

# Ingestors
BaseIngestor, IngestorError, REGISTRY
register_ingestor, get_by_format, auto_detect

# Dedup / Merge
merge_findings, merge_instances

# Diff
diff_findings, DiffResult, ChangedFinding

# Workflow
StatusWorkflow, DEFAULT_TRANSITIONS

# Utilities (from tarmo_vuln_core.utils)
slugify, get_xml_text, severity_from_cvss, detect_language
```

Additional modules imported directly: `tarmo_vuln_core.dedup`, `tarmo_vuln_core.correlator`, `tarmo_vuln_core.enrichment.nvd`, `tarmo_vuln_core.enrichment.llm`, `tarmo_vuln_core.library`, `tarmo_vuln_core.network.host_auth`, `tarmo_vuln_core.signing` (PDF + detached signers, keygen).

## Requirements

- Python 3.10+
- Rust toolchain (for building the extension) — install via [rustup](https://rustup.rs/)

## Setup

```bash
# Clone and enter the repo
git clone git@github.com:Tarmo-Technologies/tarmo-vuln-core.git
cd tarmo-vuln-core

# Create a virtualenv and install in dev mode
uv venv
uv pip install -e ".[dev]"

# Build the Rust extension
.venv/bin/maturin develop --release

# Verify
.venv/bin/python -c "import tarmo_vuln_core; print(tarmo_vuln_core.__version__)"
.venv/bin/python -c "import vuln_core_rs; print(vuln_core_rs.version())"
```

## Project Structure

```
tarmo-vuln-core/
├── pyproject.toml              # maturin build backend + project metadata
├── Cargo.toml                  # Rust workspace root
├── rust/
│   ├── Cargo.toml              # vuln-core-rs crate (cdylib + rlib)
│   └── src/
│       ├── lib.rs              # PyO3 module exports
│       ├── dedup.rs            # xxHash64 deduplication
│       └── correlator.rs       # 3-tier correlation pipeline
├── tarmo_vuln_core/
│   ├── __init__.py             # Public API exports
│   ├── models/                 # Pydantic v2 data models
│   ├── ingestors/              # 37 built-in parsers + plugin loader
│   ├── dedup/                  # Dedup engine + merge logic
│   ├── correlator/             # Correlation engine
│   ├── enrichment/             # NVD + LLM enrichment
│   ├── library/                # Finding library loader/matcher/checker
│   ├── finding_library/        # Built-in YAML definitions (web, auth, api, network, cloud, sast, secrets)
│   ├── cdata/                  # CData CWE mapping JSON for SAST tools
│   ├── network/                # Shared host/scope authorization primitives
│   ├── signing/                # PAdES-T PDF signing + ECDSA detached .sig
│   ├── diff.py                 # Before/after diff engine
│   ├── workflow.py             # Status transition engine
│   └── utils.py                # slugify, XML helpers, severity_from_cvss, detect_language
└── tests/
```

## Development

### Run Tests

```bash
# Unit tests only (no Rust extension needed)
.venv/bin/pytest tests/ -m unit

# Integration tests (requires maturin develop)
.venv/bin/pytest tests/ -m integration

# Full suite with coverage
.venv/bin/pytest tests/ -v --cov=tarmo_vuln_core --cov-fail-under=80
```

### Lint and Type Check

```bash
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy tarmo_vuln_core/
```

### Rust Development

```bash
# Check compilation without a full build
cargo check -p vuln-core-rs

# Rebuild the extension after Rust changes
.venv/bin/maturin develop --release

# Run Rust tests
cargo test -p vuln-core-rs
```

## CI

Four parallel jobs run on every push and PR to `main`:

| Job | What it does |
|---|---|
| **lint** | `ruff check` + `ruff format --check` |
| **cargo-check** | `cargo check -p vuln-core-rs` |
| **test** | Matrix across Python 3.11 and 3.12 — builds extension, runs pytest with coverage |
| **typecheck** | `mypy tarmo_vuln_core/` |

## License

Apache License 2.0. Copyright (c) 2025 Tarmo Technologies.
