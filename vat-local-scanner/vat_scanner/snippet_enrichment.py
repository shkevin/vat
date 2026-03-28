"""Enrich findings with line preview when scanner omits it. Structure-based: any vat-local report
with file path + line info is enriched automatically."""

from __future__ import annotations

import re
from pathlib import Path

MASK = "***REDACTED***"


def _read_line_at(
    scan_root: Path,
    file_path: str,
    line_num: int,
    cache: dict[tuple[str, int], str | None] | None = None,
) -> str | None:
    """Read a single line from file_path (relative to scan_root). Returns None on failure."""
    if not file_path or line_num < 1:
        return None
    path = Path(file_path)
    if path.is_absolute():
        return None
    full_path = (scan_root / path).resolve()
    key = (str(full_path), int(line_num))
    if cache is not None and key in cache:
        return cache[key]
    if not full_path.is_file():
        return None
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as fp:
            for i, line in enumerate(fp, start=1):
                if i == line_num:
                    out = line.rstrip("\n\r")
                    if cache is not None:
                        cache[key] = out
                    return out
    except OSError:
        return None
    if cache is not None:
        cache[key] = None
    return None


def _mask_secret_in_line(line: str, secret: str) -> str:
    """Replace secret in line with mask. Returns trimmed line."""
    if not line or not isinstance(line, str):
        return ""
    line = line.strip()
    if not line:
        return ""
    if secret and isinstance(secret, str) and secret.strip():
        escaped = re.escape(secret.strip())
        line = re.sub(escaped, MASK, line, flags=re.IGNORECASE)
    return line[:512]  # Cap length for DB


def _enrich_finding_with_file_line(
    f: dict,
    scan_root: Path,
    read_cache: dict[tuple[str, int], str | None] | None = None,
    *,
    path_keys: tuple[str, ...] = ("File", "file", "path"),
    line_keys: tuple[str, ...] = ("StartLine", "start_line", "line"),
    content_keys: tuple[str, ...] = ("Content", "content", "Line"),
    secret_keys: tuple[str, ...] = ("Secret", "Match", "match"),
    out_key: str = "Content",
) -> None:
    """Enrich a finding that has file path + line number. Mutates f."""
    file_path = None
    for k in path_keys:
        v = f.get(k)
        if v and isinstance(v, str):
            file_path = v.strip()
            break
    if not file_path:
        return
    line_num = None
    for k in line_keys:
        v = f.get(k)
        if v is not None:
            try:
                line_num = int(v)
                break
            except (TypeError, ValueError):
                pass
    if not line_num or line_num < 1:
        return
    for k in content_keys:
        v = f.get(k)
        if v and isinstance(v, str) and len(v.strip()) > 3:
            return
    line_content = _read_line_at(scan_root, file_path, line_num, read_cache)
    if not line_content or not line_content.strip():
        return
    secret = ""
    for k in secret_keys:
        v = f.get(k)
        if v and isinstance(v, str):
            secret = v
            break
    masked = _mask_secret_in_line(line_content, secret)
    if masked:
        f[out_key] = masked


def _enrich_result_with_secrets(
    res: dict,
    scan_root: Path,
    read_cache: dict[tuple[str, int], str | None] | None = None,
    *,
    target_keys: tuple[str, ...] = ("Target", "target"),
    secrets_keys: tuple[str, ...] = ("Secrets", "secrets"),
) -> None:
    """Enrich Results[].Secrets (Trivy-style). Target must be file path (before normalize)."""
    file_path = None
    for k in target_keys:
        v = res.get(k)
        if v:
            file_path = str(v).strip()
            break
    if not file_path:
        return
    secrets = []
    for k in secrets_keys:
        v = res.get(k)
        if isinstance(v, list):
            secrets = v
            break
    for s in secrets:
        if not isinstance(s, dict):
            continue
        raw_code = s.get("Code") or s.get("code")
        if not isinstance(raw_code, dict):
            continue
        lines_arr = raw_code.get("Lines") or raw_code.get("lines") or []
        if not lines_arr or not isinstance(lines_arr[0], dict):
            continue
        first_line = lines_arr[0]
        existing = first_line.get("Content") or first_line.get("content")
        if existing and isinstance(existing, str) and len(existing.strip()) > 3:
            continue
        line_num = first_line.get("Number") or first_line.get("LineNumber") or first_line.get("line")
        if line_num is None:
            continue
        try:
            line_num = int(line_num)
        except (TypeError, ValueError):
            continue
        if line_num < 1:
            continue
        line_content = _read_line_at(scan_root, file_path, line_num, read_cache)
        if not line_content or not line_content.strip():
            continue
        match = s.get("Match") or s.get("match") or ""
        masked = _mask_secret_in_line(line_content, match)
        if masked:
            first_line["Content"] = masked


def _enrich_result_with_path_start(
    r: dict,
    scan_root: Path,
    read_cache: dict[tuple[str, int], str | None] | None = None,
    *,
    path_key: str = "path",
    start_key: str = "start",
    line_key: str = "line",
    extra_key: str = "extra",
    lines_key: str = "lines",
) -> None:
    """Enrich result with path + start.line (Semgrep-style)."""
    path = (r.get(path_key) or "").strip()
    if not path:
        return
    start = r.get(start_key) or {}
    if not isinstance(start, dict):
        return
    line_num = start.get(line_key)
    if line_num is None:
        return
    try:
        line_num = int(line_num)
    except (TypeError, ValueError):
        return
    if line_num < 1:
        return
    extra = r.get(extra_key) or {}
    existing = extra.get(lines_key)
    if existing and isinstance(existing, str) and len(existing.strip()) > 3:
        return
    line_content = _read_line_at(scan_root, path, line_num, read_cache)
    if line_content and line_content.strip():
        if extra_key not in r:
            r[extra_key] = {}
        r[extra_key][lines_key] = line_content[:512]


def _enrich_report(report: dict | list | None, scan_root: Path) -> None:
    """Enrich a single report based on its structure. Mutates in place."""
    if report is None or not Path(scan_root).is_dir():
        return
    scan_root = Path(scan_root)
    read_cache: dict[tuple[str, int], str | None] = {}

    # Structure: findings/Findings array (Gitleaks-style)
    findings = None
    if isinstance(report, list):
        findings = report
    elif isinstance(report, dict):
        findings = report.get("findings") or report.get("Findings")
    if findings and isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                _enrich_finding_with_file_line(f, scan_root, read_cache)
        return

    if not isinstance(report, dict):
        return

    # Structure: Results with Target + Secrets (Trivy-style; Target must exist before normalize)
    results = report.get("Results") or report.get("results")
    if results and isinstance(results, list):
        for res in results:
            if isinstance(res, dict) and (res.get("Secrets") or res.get("secrets")):
                _enrich_result_with_secrets(res, scan_root, read_cache)
                continue
            # Structure: results with path + start (Semgrep-style)
            if isinstance(res, dict) and res.get("path") and res.get("start"):
                _enrich_result_with_path_start(res, scan_root, read_cache)


def enrich_reports(reports: dict, scan_root: Path) -> None:
    """Enrich any vat-local report with line preview when content is missing. Structure-based."""
    if not reports or not scan_root:
        return
    scan_root = Path(scan_root)
    for report in reports.values():
        _enrich_report(report, scan_root)
