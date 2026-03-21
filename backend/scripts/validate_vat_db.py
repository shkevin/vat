#!/usr/bin/env python3
"""
Query VAT DB findings and compare with Excel baseline.
Run: uv run python scripts/validate_vat_db.py [path/to/excel.xlsx]
"""

import asyncio
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app.core.database import async_session
from app.models.finding import Finding


def _status_display(s) -> str:
    """VAT display status (same as frontend)."""
    if s is None:
        return ""
    val = s.value if hasattr(s, "value") else str(s)
    return (
        str(val)
        .replace("_", " ")
        .replace("SyncedToTracker", "Synced to Tracker")
        .replace("InReview", "In Review")
        .replace("FalsePositive", "False Positive")
        .replace("NotApplicable", "Not Applicable")
        .replace("RiskAccepted", "Risk Accepted")
    )


async def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path and Path(path).exists():
        try:
            import pandas as pd

            df = pd.read_excel(path, sheet_name="Issues")
            df = df.rename(
                columns=lambda c: c.strip().lower().replace(" ", "_")
                if isinstance(c, str)
                else c
            )
            repo_col = (
                "repository"
                if "repository" in df.columns
                else next(
                    (c for c in df.columns if "repo" in str(c).lower()), "repository"
                )
            )
            vat_col = "vat_status" if "vat_status" in df.columns else None
            excel_by_asset: dict[str, dict] = defaultdict(
                lambda: {"total": 0, "Open": 0, "Resolved": 0, "Suppressed": 0}
            )
            for _, row in df.iterrows():
                asset = str(row.get(repo_col, "")).strip() or "unknown"
                if asset.lower() == "nan":
                    asset = "unknown"
                excel_by_asset[asset]["total"] += 1
                # Use vat_status when present (ignored->Suppressed)
                st = str(row.get(vat_col, "") or "").strip() if vat_col else ""
                if st:
                    excel_by_asset[asset][st] = excel_by_asset[asset].get(st, 0) + 1
                else:
                    raw = str(row.get("status", "") or "").lower()
                    if raw == "open":
                        excel_by_asset[asset]["Open"] += 1
                    elif raw in ("closed", "resolved"):
                        excel_by_asset[asset]["Resolved"] += 1
                    elif raw in ("ignored", "suppressed"):
                        excel_by_asset[asset]["Suppressed"] += 1
            excel_data = dict(excel_by_asset)
            print(f"Excel baseline: {path}\n")
        except Exception as e:
            print(f"Could not read Excel: {e}")
            excel_data = None
    else:
        excel_data = None

    async with async_session() as session:
        result = await session.execute(
            select(Finding)
            .where(Finding.archived == False)
            .where(Finding.source == "Aikido")
        )
        findings = list(result.scalars().all())

    # Group by asset (image or component)
    by_asset: dict[str, list] = defaultdict(list)
    for f in findings:
        asset = (f.image or f.component or "unknown").strip() or "unknown"
        by_asset[asset].append(f)

    print("=" * 80)
    print("VAT DATABASE — Aikido findings")
    print("=" * 80)
    print(f"Total Aikido findings in DB: {len(findings)}")
    print()

    CLOSED = {
        "Resolved",
        "False Positive",
        "Duplicate",
        "Not Applicable",
        "Approved",
        "Suppressed",
    }
    all_ok = True

    for asset in sorted(by_asset.keys()):
        rows = by_asset[asset]
        total = len(rows)

        status_counts: dict[str, int] = defaultdict(int)
        for f in rows:
            disp = _status_display(f.status)
            status_counts[disp] += 1

        open_findings = [f for f in rows if _status_display(f.status) not in CLOSED]
        open_count = len(open_findings)

        print("-" * 80)
        print(f"ASSET: {asset}")
        print("-" * 80)
        print(f"  Total:     {total}")
        print(f"  Open:      {open_count}  (excludes Resolved, Suppressed, etc.)")
        print()
        print("  Status breakdown:")
        for s, n in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"    {s or '(blank)'}: {n}")
        print()

        if excel_data and asset in excel_data:
            ex = excel_data[asset]
            ex_total = ex.get("total", 0)
            ex_open = ex.get("Open", 0)
            match_total = total == ex_total
            match_open = open_count == ex_open
            if not match_total or not match_open:
                all_ok = False
            print("  vs Excel:")
            print(
                f"    Total:  VAT={total}  Excel={ex_total}  {'OK' if match_total else 'MISMATCH'}"
            )
            print(
                f"    Open:   VAT={open_count}  Excel={ex_open}  {'OK' if match_open else 'MISMATCH'}"
            )
            print()
        print()

    if excel_data:
        ex_total_all = sum(d.get("total", 0) for d in excel_data.values())
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"VAT total:   {len(findings)}")
        print(f"Excel total: {ex_total_all}")
        print(
            f"Match: {'YES' if len(findings) == ex_total_all and all_ok else 'NO - investigate'}"
        )
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
