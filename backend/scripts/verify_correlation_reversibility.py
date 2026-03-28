#!/usr/bin/env python3
"""Repeatable quality gate for correlation reversibility features.

Runs migrations + targeted tests, then enforces coverage thresholds for:
- correlation edge service module
- correlation API handler block in app/api/findings.py
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE_JSON = ROOT / "coverage-correlation.json"

SERVICE_FILE_KEY = "app/services/correlation_edges.py"
API_FILE_KEY = "app/api/findings.py"
SERVICE_MIN = 90.0
API_BLOCK_MIN = 90.0

TEST_ARGS = [
    "tests/test_correlation_edges_service.py",
    "tests/test_crosswalks_service.py",
    "tests/test_correlation_scoring.py",
    "tests/test_findings_correlation_edges_api.py",
    "tests/test_findings_correlation_handlers_unit.py",
    "tests/test_correlation_linking.py",
    "tests/test_correlation_linking_contract.py",
]

API_FUNCTIONS = {
    "get_finding_correlations",
    "remove_finding_correlation",
    "restore_finding_correlation",
    "get_finding_correlation_history",
    "get_correlation_operation_history",
    "post_crosswalk_run",
    "get_crosswalk_resolve",
}


def _run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def _pct_for_file(file_data: dict) -> float:
    executed = set(file_data.get("executed_lines", []))
    missing = set(file_data.get("missing_lines", []))
    total = len(executed | missing)
    return (100.0 * len(executed) / total) if total else 100.0


def _api_block_lines() -> set[int]:
    src = (ROOT / "app" / "api" / "findings.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name in API_FUNCTIONS:
            start = int(node.lineno)
            end = int(getattr(node, "end_lineno", node.lineno))
            lines.update(range(start, end + 1))
    return lines


def _pct_for_line_subset(file_data: dict, lines_subset: set[int]) -> float:
    executed = set(file_data.get("executed_lines", []))
    missing = set(file_data.get("missing_lines", []))
    statement_lines = (executed | missing) & lines_subset
    if not statement_lines:
        return 100.0
    return 100.0 * len(executed & statement_lines) / len(statement_lines)


def main() -> int:
    _run(["uv", "run", "alembic", "upgrade", "head"])
    _run(
        [
            "uv",
            "run",
            "pytest",
            *TEST_ARGS,
            "--cov=app.api.findings",
            "--cov=app.services.correlation_edges",
            "--cov=app.services.crosswalks",
            "--cov=app.services.correlation_scoring",
            "--cov-report=term-missing",
            f"--cov-report=json:{COVERAGE_JSON.name}",
            "-q",
        ]
    )

    cov = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    files = cov["files"]
    service_pct = _pct_for_file(files[SERVICE_FILE_KEY])
    api_block_pct = _pct_for_line_subset(files[API_FILE_KEY], _api_block_lines())

    print(f"service_coverage={service_pct:.1f}% (min {SERVICE_MIN:.1f}%)")
    print(f"api_block_coverage={api_block_pct:.1f}% (min {API_BLOCK_MIN:.1f}%)")

    failures = []
    if service_pct < SERVICE_MIN:
        failures.append("correlation_edges service coverage below threshold")
    if api_block_pct < API_BLOCK_MIN:
        failures.append("findings correlation API block coverage below threshold")

    if failures:
        print("QUALITY GATE FAILED:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("QUALITY GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

