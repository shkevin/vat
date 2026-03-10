"""Export Aikido sync data to Excel for validation and leadership reporting.

When VAT_AIKIDO_EXPORT_EXCEL_DIR is set, each sync writes a timestamped .xlsx file
so data scientists can verify counts, grouping, and display logic.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _flatten_for_excel(obj: Any) -> Any:
    """Convert nested dict/list to Excel-friendly value (string if complex)."""
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, dict)):
        return json.dumps(obj, default=str)[:32767]  # Excel cell limit
    return str(obj)


def _rows_from_dicts(items: list[dict], exclude_keys: set[str] | None = None) -> list[dict]:
    """Flatten list of dicts for Excel; nested values become JSON strings."""
    exclude = exclude_keys or set()
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        row = {}
        for k, v in item.items():
            if k in exclude:
                continue
            row[k] = _flatten_for_excel(v)
        rows.append(row)
    return rows


def _ensure_columns(rows: list[dict], column_order: list[str] | None = None) -> list[dict]:
    """Ensure all rows have same columns; fill missing with empty string."""
    if not rows:
        return rows
    all_keys = set()
    for r in rows:
        all_keys.update(r.keys())
    ordered = column_order or sorted(all_keys)
    return [{k: r.get(k, "") for k in ordered} for r in rows]


def export_aikido_sync_to_excel(
    data: dict,
    raw_issues: list[dict] | None = None,
    output_dir: str | Path | None = None,
) -> str | None:
    """
    Write Aikido sync data to an Excel file for validation.

    Creates sheets: Summary, Issues (normalized), IssueGroups, RawIssues (sample),
    Repos, Containers, VMs, IssueCounts.

    Returns the path of the written file, or None if output_dir is not set or write fails.
    """
    if not output_dir:
        logger.debug("export_aikido_sync_to_excel: output_dir is empty, skipping")
        return None

    out_path = Path(output_dir)
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.exception("Cannot create export dir %s: %s", output_dir, e)
        return None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    filepath = out_path / f"aikido_sync_{ts}.xlsx"

    try:
        import pandas as pd
    except ImportError:
        logger.warning("pandas not installed; skipping Aikido Excel export. pip install pandas openpyxl")
        return None

    try:
        with pd.ExcelWriter(filepath, engine="openpyxl") as writer:
            # Summary sheet
            summary = {
                "Metric": [
                    "Fetched At",
                    "Issues (normalized)",
                    "Issue Groups",
                    "Repos",
                    "Containers",
                    "VMs",
                    "Raw Issues (export)",
                ],
                "Value": [
                    data.get("fetchedAt", ""),
                    len(data.get("issues", [])),
                    len(data.get("issueGroups", [])),
                    len(data.get("repos", [])),
                    len(data.get("containers", [])),
                    len(data.get("vms", [])),
                    len(raw_issues) if raw_issues else 0,
                ],
            }
            pd.DataFrame(summary).to_excel(writer, sheet_name="Summary", index=False)

            # Issue counts (Aikido authoritative)
            counts = data.get("issueCounts") or data.get("issue_counts")
            if isinstance(counts, dict):
                counts_flat = [{"key": k, "value": _flatten_for_excel(v)} for k, v in counts.items()]
                pd.DataFrame(counts_flat).to_excel(writer, sheet_name="IssueCounts", index=False)
            elif isinstance(counts, list):
                pd.DataFrame(counts).to_excel(writer, sheet_name="IssueCounts", index=False)

            # Normalized issues (what VAT uses for display)
            issues = data.get("issues", [])
            if issues:
                rows = _rows_from_dicts(issues)
                rows = _ensure_columns(rows)
                pd.DataFrame(rows).to_excel(writer, sheet_name="Issues", index=False)

            # Issue groups
            groups = data.get("issueGroups", data.get("issue_groups", []))
            if groups:
                rows = _rows_from_dicts(groups)
                rows = _ensure_columns(rows)
                pd.DataFrame(rows).to_excel(writer, sheet_name="IssueGroups", index=False)

            # Raw issues (full Aikido export for validation)
            raw = raw_issues or []
            if raw:
                rows = _rows_from_dicts(raw)
                rows = _ensure_columns(rows)
                pd.DataFrame(rows).to_excel(writer, sheet_name="RawIssues", index=False)

            # Repos, Containers, VMs
            for name, key in [("Repos", "repos"), ("Containers", "containers"), ("VMs", "vms")]:
                items = data.get(key, [])
                if items:
                    rows = _rows_from_dicts(items)
                    rows = _ensure_columns(rows)
                    pd.DataFrame(rows).to_excel(writer, sheet_name=name, index=False)

        logger.info("Aikido sync data exported to %s", filepath)
        return str(filepath)
    except Exception as e:
        logger.exception("Failed to export Aikido sync to Excel: %s", e)
        return None
