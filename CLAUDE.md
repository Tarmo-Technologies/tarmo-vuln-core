# tarmo-vuln-core — Claude Code Development Guide

## Project Overview

`tarmo-vuln-core` is a hybrid Python+Rust shared vulnerability processing library used by pentest-scribe and other Tarmo security tools. It provides normalized models, parsers, deduplication/merge logic, finding enrichment, and a diff engine — with performance-critical paths implemented in Rust via PyO3.

Requires Python 3.10+ and (for the Rust extension) a Rust toolchain.

## Repository Structure

See the **Project Structure** section of [README.md](README.md) for the full source tree.

The Python package (`tarmo_vuln_core`) loads without the Rust extension (`vuln_core_rs`), so pure-Python usage works without a Rust toolchain.

## Common Commands

```bash
# Setup
uv venv
uv pip install -e ".[dev]"
.venv/bin/maturin develop --release

# Fallback if uv is not installed:
# python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
# .venv/bin/maturin develop --release

# Run tests
.venv/bin/pytest tests/ -q --tb=short            # all tests
.venv/bin/pytest tests/ -m unit                   # unit only
.venv/bin/pytest tests/ -m integration            # integration only
.venv/bin/pytest tests/ -v --cov=tarmo_vuln_core --cov-fail-under=80  # with coverage

# Lint / Format / Type Check
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy tarmo_vuln_core/

# Rust
cargo check -p vuln-core-rs
.venv/bin/maturin develop --release
cargo test -p vuln-core-rs
```

Coverage target: **>=80%**. CI enforces `--cov-fail-under=80`.

### Pre-Push Checklist (MANDATORY)

Run **ALL** of these before every `git push`. CI failures from locally-catchable issues waste minutes.

```bash
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy tarmo_vuln_core/
.venv/bin/pytest tests/ -q --tb=short
```

If ANY check fails, fix it before pushing. Never push code that hasn't passed all checks locally.

## TDD Red-Green Workflow (Required)

**Every piece of code written in this repo must follow TDD red-green:**

1. **Write a failing test first** — run it to confirm it fails with the expected error (red).
2. **Write the minimal code to make it pass** — run again to confirm green.
3. **Refactor** if needed, keeping tests green.

This is not optional. Do not write production code before writing the test that exercises it. Tests must be legitimate — they should fail if the implementation is wrong, not just be structural boilerplate.

> **VIOLATION CHECK**: Before writing ANY line of production code, verify there
> is a failing test for it. If there is not, STOP and write the test first.
> Show the RED (failing) output before writing any implementation code.
> Commits must follow: `test: add failing tests` then `feat: implement`.

**Running tests to verify red/green:**
```bash
.venv/bin/pytest tests/test_file.py::test_name -x   # single test (verify red before implementing)
.venv/bin/pytest tests/ -q --tb=short                # full suite (must stay green)
```

### Rust-Specific Test Patterns

- Use `cargo test -p vuln-core-rs` for Rust unit tests.
- For Python integration tests that depend on the Rust extension, use `pytest.importorskip("vuln_core_rs")` at the top of the test module or in a fixture.
- Rust changes require `maturin develop --release` before running Python integration tests.

## Anti-Rubber-Stamp Rules (CRITICAL)

A **rubber-stamp test** is one that passes trivially without verifying real behaviour — it is worse than no test because it creates false confidence. **Never write rubber-stamp tests.**

Red flags that indicate a rubber-stamp test:
- `assert True` or `assert result is not None` with no further assertions
- Assertions that only check a return type, not the actual value (e.g. `assert isinstance(x, list)`)
- Tests that `mock.patch` the very function under test so it never actually runs
- Tests on stubs that only `return ""` / `return b""` / `raise NotImplementedError` without asserting the stub eventually gets replaced by a real implementation
- Smoke tests that assert `len(results) > 0` without pinning at least one specific field value
- Tests that pass even when the implementation is deleted (dead assertions)

Required for every test:
- Assert at least one **specific, concrete value** (e.g. exact count, exact field content, exact error message) that would fail if the implementation were wrong or missing.
- For parser tests: assert exact finding count **and** at least one specific field value (title, CVE, host, severity).
- For CLI tests: assert the exit code **and** at least one substring of stdout/stderr output.

Before committing any new test file, mentally delete the implementation and ask: "Would this test fail?" If the answer is "no" or "maybe not", the test is a rubber stamp — rewrite it.

## Code Style

- Follow PEP 8; enforced by `ruff`.
- Use Pydantic v2 model validators for cross-field validation.
- Parsers must be stateless — no instance state between `parse()` calls.
- Prefer `Path` objects over raw strings for all file paths.
- Raise descriptive exceptions rather than returning `None` on failure.

## Out of Scope (Do Not Implement Unless Asked)

- GUI / web interface — library only.
- Cloud sync or multi-user collaboration — single-user, local development.
- Application-level CLI — downstream consumers (e.g. pentest-scribe) own the CLI layer.
