# Contributing to tarmo-vuln-core

Thank you for your interest in contributing! This guide covers everything you need to get started.

`tarmo-vuln-core` is a hybrid Python + Rust library. Most contributions are pure Python and need
no Rust toolchain; changes under `rust/` require [rustup](https://rustup.rs/) and `maturin`.

## Development Setup

```bash
uv venv
uv pip install -e ".[dev]"

# Fallback if uv is not installed:
# python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# Build the Rust extension (only needed for integration tests / Rust changes)
.venv/bin/maturin develop --release
```

Requires **Python 3.10+**.

## Running Tests

```bash
# Pure-Python unit tests (no Rust extension needed)
.venv/bin/pytest tests/ -m unit

# Integration tests (requires `maturin develop`)
.venv/bin/pytest tests/ -m integration

# Full suite with coverage (mirrors CI)
.venv/bin/pytest tests/ -q --cov=tarmo_vuln_core --cov-fail-under=80
```

Coverage target: **≥80%**. CI enforces `--cov-fail-under=80`.

## Lint / Format / Type Check

```bash
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy tarmo_vuln_core/
```

For Rust changes:

```bash
cargo check -p vuln-core-rs
cargo test -p vuln-core-rs
```

All checks must pass before a PR can be merged. CI enforces them automatically.

## TDD Discipline

Follow **Red → Green → Refactor**:

1. Write the test first. Run `pytest tests/ -x` — confirm it fails.
2. Write the minimal implementation to make the test pass.
3. Refactor while keeping tests green.

**Never write rubber-stamp tests.** Every test must assert at least one specific, concrete value
that would fail if the implementation were removed. For parser tests this means asserting the exact
finding count and at least one specific field value (title, CVE, host, severity) derived from
inspecting a real fixture file.

## Adding a New Parser

Built-in parsers live under `tarmo_vuln_core/ingestors/parsers/`.

1. Create `tarmo_vuln_core/ingestors/parsers/<name>.py` subclassing `BaseIngestor`.
2. Implement `can_handle(path: Path) -> bool` and `ingest(path: Path) -> list[Finding]`.
3. Parsers must be **stateless** — no instance state between `ingest()` calls.
4. Use a real fixture file from a public source (never hand-craft XML/JSON). Note the source URL in
   a comment above the smoke test.
5. Write a smoke test asserting the **exact finding count** and at least **one specific field
   value** from the real fixture.
6. Register the parser in the parsers `__init__.py` registry.
7. Add a row to the **Supported Parsers** table in `README.md`.

## Branch and PR Workflow

- Branch off `main`: use `feature/short-description` or `fix/issue-number`.
- One feature or fix per PR.
- All CI checks (lint, typecheck, test, cargo-check) must pass.
- Update `README.md` if user-facing behaviour changes.

## Commit Style

Use imperative mood with a conventional prefix:

```
feat: add Coverity JSON parser
fix: handle Nessus files with empty host blocks
docs: update parser table for the SARP importer
refactor: extract severity normalisation into shared helper
test: add smoke test for ZAP parser with real fixture
```

## Reporting Issues

- **Bugs and feature requests**: open a [GitHub issue](https://github.com/Tarmo-Technologies/tarmo-vuln-core/issues/new).
- **Security vulnerabilities**: see [SECURITY.md](SECURITY.md) — do NOT open a public issue.
