# Pre-Commit Check

Run all quality gates on the tarmo-vuln-core codebase and report results.

Run from the repository root.

Run these commands in sequence (do NOT stop on first failure — run all four):

```bash
echo "=== ruff check ===" && .venv/bin/ruff check . 2>&1; RUFF_CHECK=$?
echo "=== ruff format ===" && .venv/bin/ruff format --check . 2>&1; RUFF_FMT=$?
echo "=== mypy ===" && .venv/bin/mypy tarmo_vuln_core/ 2>&1; MYPY=$?
echo "=== cargo check ===" && cargo check -p vuln-core-rs 2>&1; CARGO=$?
```

Report a clean summary table:

| Gate | Result |
|---|---|
| ruff check | PASS / FAIL |
| ruff format | PASS / FAIL |
| mypy | PASS / FAIL |
| cargo check | PASS / FAIL |

If any gate failed, include only the relevant error lines (not full output). If all pass, say so in one line.
