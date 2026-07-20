"""Import built-in CData defaults from a CSV export."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from tarmo_vuln_core.cdata import _MAPPINGS_DIR, discover_tool_files

_SCANNER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bcpp\s*check\b", re.IGNORECASE), "cppcheck"),
    (re.compile(r"\bpylint\b", re.IGNORECASE), "pylint"),
    (re.compile(r"\bsrm\b|security risk management", re.IGNORECASE), "srm"),
    (re.compile(r"owasp\s+dependency\s+check", re.IGNORECASE), "owasp-depcheck"),
    (re.compile(r"checkmarx", re.IGNORECASE), "checkmarx"),
    (re.compile(r"eslint", re.IGNORECASE), "eslint"),
    (re.compile(r"sigasi", re.IGNORECASE), "sigasi"),
)


@dataclass(slots=True)
class ImportSummary:
    rows_total: int = 0
    rows_imported: int = 0
    rows_skipped_existing: int = 0
    rows_skipped_invalid: int = 0
    tools_created: list[str] = field(default_factory=list)
    tools_extended: list[str] = field(default_factory=list)
    unmatched_scanners: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["tools_created"] = sorted(set(self.tools_created))
        payload["tools_extended"] = sorted(set(self.tools_extended))
        payload["unmatched_scanners"] = sorted(set(self.unmatched_scanners))
        return payload


def normalize_scanner_name(scanner: str) -> str | None:
    """Normalize versioned scanner labels to stable CData tool names."""
    normalized = scanner.strip()
    if not normalized:
        return None
    for pattern, tool in _SCANNER_PATTERNS:
        if pattern.search(normalized):
            return tool
    return None


def _load_mapping(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    result: dict[str, dict[str, object]] = json.loads(path.read_text(encoding="utf-8"))
    return result


def _write_mapping(path: Path, mapping: dict[str, dict[str, object]]) -> None:
    path.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def import_defaults_from_csv(
    csv_path: Path, *, mappings_dir: Path = _MAPPINGS_DIR
) -> ImportSummary:
    """Import valid missing rows from a CSV into built-in CData mapping files."""
    summary = ImportSummary()
    tool_files = discover_tool_files(mappings_dir)
    loaded: dict[str, dict[str, dict[str, object]]] = {
        tool: _load_mapping(path) for tool, path in tool_files.items()
    }

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            summary.rows_total += 1
            scanner = str(row.get("Scanner", "")).strip()
            tool = normalize_scanner_name(scanner)
            if tool is None:
                summary.rows_skipped_invalid += 1
                if scanner:
                    summary.unmatched_scanners.append(scanner)
                continue

            query = str(row.get("Type", "")).strip()
            cwe_text = str(row.get("CWE", "")).strip()
            if not query or not cwe_text.isdigit():
                summary.rows_skipped_invalid += 1
                continue

            tool_mapping = loaded.setdefault(tool, {})
            mapping_path = mappings_dir / f"{tool}.json"
            if tool not in tool_files and tool not in summary.tools_created:
                summary.tools_created.append(tool)

            if query in tool_mapping:
                summary.rows_skipped_existing += 1
                continue

            entry: dict[str, object] = {"cwe": int(cwe_text)}
            if str(row.get("Confidence", "")).strip() == "Inform":
                entry["confidence"] = "Inform"
            tool_mapping[query] = entry
            summary.rows_imported += 1
            summary.tools_extended.append(tool)

            _write_mapping(mapping_path, tool_mapping)
            tool_files[tool] = mapping_path

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--mappings-dir", type=Path, default=_MAPPINGS_DIR)
    parser.add_argument("--summary-json", type=Path, default=None)
    args = parser.parse_args(argv)

    summary = import_defaults_from_csv(args.csv_path, mappings_dir=args.mappings_dir)
    payload = summary.to_dict()
    if args.summary_json is not None:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
