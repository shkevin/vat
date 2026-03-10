#!/usr/bin/env python3
"""
Independent audit of Aikido Excel export.

Reads the Excel file and computes per-asset metrics using ONLY the raw data
in the file — no VAT logic, formulas, or assumptions. This provides an
independent baseline to compare against VAT's displayed data.

Run: uv run python scripts/validate_excel_vat.py [path/to/export.xlsx]
"""

import sys
from pathlib import Path
from collections import defaultdict


def main() -> None:
    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        sys.exit(1)

    path = sys.argv[1] if len(sys.argv) > 1 else "data/exports/aikido_sync_2026-02-27_122751.xlsx"
    if not Path(path).exists():
        path = Path(__file__).resolve().parent.parent.parent / "data" / "exports" / Path(path).name
    if not Path(path).exists():
        exports = Path(__file__).resolve().parent.parent.parent / "data" / "exports"
        if exports.exists():
            files = sorted(exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
            if files:
                path = files[0]
                print(f"Using latest export: {path.name}\n")
    path = Path(path)
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    df = pd.read_excel(path, sheet_name="Issues")
    if df.empty:
        print("No Issues sheet or empty")
        sys.exit(1)

    # Use column names as-is from Excel
    df = df.rename(columns=lambda c: c.strip().lower().replace(" ", "_") if isinstance(c, str) else c)

    # Identify asset column — whatever the export uses for repository/container
    repo_col = None
    for cand in ("repository", "code_repo_name", "container_repo_name"):
        if cand in df.columns:
            repo_col = cand
            break
    if repo_col is None:
        repo_col = [c for c in df.columns if "repo" in c.lower()][0] if any("repo" in str(c).lower() for c in df.columns) else None
    if repo_col is None and "affected_package" in df.columns:
        repo_col = "affected_package"  # fallback
    if repo_col is None:
        print("No repository/asset column found. Columns:", list(df.columns))
        sys.exit(1)

    status_col = "status" if "status" in df.columns else None
    vat_status_col = "vat_status" if "vat_status" in df.columns else None
    sev_col = "severity" if "severity" in df.columns else None

    # Build asset -> list of rows (raw data only)
    by_asset: dict[str, list[dict]] = defaultdict(list)
    for _, row in df.iterrows():
        asset = str(row.get(repo_col, "")).strip() or "unknown"
        if asset.lower() == "nan":
            asset = "unknown"
        raw_status = str(row.get(status_col, "")).strip() if status_col else ""
        vat_status = str(row.get(vat_status_col, "")).strip() if vat_status_col else ""
        rec = {
            "status": raw_status.lower(),
            "status_raw": raw_status,
            "vat_status": vat_status,
            "severity": str(row.get(sev_col, "")).strip() if sev_col else "",
            "title": str(row.get("title", row.get("affected_package", "")))[:80],
        }
        by_asset[asset].append(rec)

    print("=" * 80)
    print("INDEPENDENT AUDIT — Raw Excel data, no VAT logic")
    print("=" * 80)
    print(f"File: {path}")
    print(f"Total rows (Issues sheet): {len(df)}")
    print(f"Asset column used: {repo_col}")
    print(f"Status column: {status_col or 'N/A'}")
    print(f"Severity column: {sev_col or 'N/A'}")
    print()

    for asset in sorted(by_asset.keys()):
        rows = by_asset[asset]
        total = len(rows)

        # Raw status counts (exactly as in Excel)
        status_counts: dict[str, int] = defaultdict(int)
        for r in rows:
            status_counts[r.get("status_raw", r["status"])] += 1

        # VAT-aligned counts when vat_status column present (ignored -> Suppressed)
        vat_status_counts: dict[str, int] = defaultdict(int)
        if any(r.get("vat_status") for r in rows):
            for r in rows:
                vat_status_counts[r.get("vat_status", "")] += 1
        vat_open = sum(1 for r in rows if (r.get("vat_status") or "").lower() == "open") if vat_status_counts else None

        # Raw severity counts (exactly as in Excel)
        sev_counts: dict[str, int] = defaultdict(int)
        for r in rows:
            sev_counts[r["severity"]] += 1

        # Simple open/closed: status (lowercase) equals "open" vs anything else
        open_count = sum(1 for r in rows if r["status"] == "open")
        closed_count = total - open_count

        print("-" * 80)
        print(f"ASSET: {asset}")
        print("-" * 80)
        print(f"  Total issues:        {total}")
        print(f"  Status = 'open':     {open_count}")
        print(f"  Status != 'open':    {closed_count}")
        if vat_open is not None:
            print(f"  VAT Open (vat_status): {vat_open}  (ignored -> Suppressed, not closed)")
        print()
        print("  Status breakdown (as in Excel):")
        for s, n in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"    {s or '(blank)'}: {n}")
        if vat_status_counts:
            print()
            print("  VAT status breakdown (ignored -> Suppressed):")
            for s, n in sorted(vat_status_counts.items(), key=lambda x: -x[1]):
                print(f"    {s or '(blank)'}: {n}")
        print()
        print("  Severity breakdown (as in Excel):")
        for s, n in sorted(sev_counts.items(), key=lambda x: -x[1]):
            print(f"    {s or '(blank)'}: {n}")
        print()
        if open_count > 0 and open_count <= 15:
            print("  Open issues (sample):")
            for r in rows:
                if r["status"] == "open":
                    print(f"    [{r['severity']}] {r['title']}")
        elif open_count > 0:
            open_rows = [r for r in rows if r["status"] == "open"]
            for r in open_rows[:5]:
                print(f"    [{r['severity']}] {r['title']}")
            print(f"    ... and {open_count - 5} more")
        print()

    print("=" * 80)
    print("Compare the above with VAT Asset page:")
    print("  - Open/closed counts should match if VAT uses same status logic")
    print("  - Severity breakdown should match if VAT uses same severity mapping")
    print("  - Any mismatch indicates a discrepancy to investigate")
    print("=" * 80)


if __name__ == "__main__":
    main()
