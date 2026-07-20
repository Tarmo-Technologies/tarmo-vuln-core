# Test Runner

Run the pytest test suite and report results.

Run from the repository root.

```bash
.venv/bin/pytest tests/ -q --tb=short 2>&1
```

Report:
- Total: X passed, Y failed, Z skipped
- For each failure: test name + the short traceback
- If all pass, say so in one line

Do NOT dump the full pytest output — only failures and the final summary line.
