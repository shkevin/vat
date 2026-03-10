#!/usr/bin/env python3
"""
Verify VAT dashboard data for kamiwaza (develop) matches the latest Excel export.

Compares:
- Excel: data/exports/aikido_sync_*.xlsx (latest) — Issues sheet, repository=kamiwaza, branch=develop
- VAT DB: findings where image=kamiwaza, branch=develop, source=Aikido

Run from backend/: uv run python scripts/verify_kamiwaza_develop.py [path/to/excel.xlsx]

Note: Excel needs branch column populated. Run a full Aikido sync (with branch enrichment)
to regenerate the export. Standalone sync-dashboard also fetches repos for branch enrichment.
"""

import asyncio
import logging

# Suppress SQLAlchemy INFO/DEBUG during verification
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.finding import Finding


ASSET = "kamiwaza"
BRANCH = "develop"
CLOSED = {"Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"}


def _status_display(s) -> str:
    """VAT display status (same as frontend)."""
    if s is None:
        return ""
    val = s.value if hasattr(s, "value") else str(s)
    return str(val).replace("_", " ").replace("SyncedToTracker", "Synced to Tracker").replace(
        "InReview", "In Review"
    ).replace("FalsePositive", "False Positive").replace("NotApplicable", "Not Applicable").replace(
        "RiskAccepted", "Risk Accepted"
    )


def load_excel_kamiwaza_develop(path: Path) -> dict | None:
    """Load Excel and return counts for kamiwaza develop."""
    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        return None

    df = pd.read_excel(path, sheet_name="Issues")
    if df.empty:
        return None

    df = df.rename(columns=lambda c: c.strip().lower().replace(" ", "_") if isinstance(c, str) else c)
    repo_col = "repository" if "repository" in df.columns else next(
        (c for c in df.columns if "repo" in str(c).lower()), "repository"
    )
    # Aikido uses separate repos per branch; no branch column. Repository is "kamiwaza (develop)" etc.
    vat_col = "vat_status" if "vat_status" in df.columns else None
    sev_col = "severity" if "severity" in df.columns else None

    rows = []
    for _, row in df.iterrows():
        asset = str(row.get(repo_col, "")).strip() or ""
        if asset.lower() == "nan":
            asset = ""

        # Aikido uses separate repos per branch: repository is "kamiwaza (develop)" for develop branch.
        # Use STRICT match only — "kamiwaza-extension-omniparse (develop)" must NOT match.
        asset_match = asset.lower() == f"{ASSET.lower()} ({BRANCH.lower()})"

        if asset_match:
            vat_status = str(row.get(vat_col, "") or "").strip() if vat_col else ""
            raw_status = str(row.get("status", "") or "").lower()
            if not vat_status:
                vat_status = "Open" if raw_status == "open" else ("Resolved" if raw_status in ("closed", "resolved") else "Suppressed")
            severity = str(row.get(sev_col, "") or "").strip() if sev_col else ""
            rows.append({"vat_status": vat_status, "severity": severity})

    if not rows:
        return None

    total = len(rows)
    status_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    for r in rows:
        status_counts[r["vat_status"]] += 1
        severity_counts[r["severity"]] += 1

    open_count = sum(1 for r in rows if (r.get("vat_status") or "").lower() == "open")
    return {
        "total": total,
        "open": open_count,
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "rows": rows,
    }


async def load_vat_db_kamiwaza_develop(session: AsyncSession) -> dict:
    """Query VAT DB for kamiwaza develop findings."""
    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.archived == False,
                Finding.source == "Aikido",
                Finding.image == ASSET,
                Finding.branch == BRANCH,
            )
        )
    )
    findings = list(result.scalars().all())

    total = len(findings)
    status_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    for f in findings:
        disp = _status_display(f.status)
        status_counts[disp] += 1
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity or ""))
        severity_counts[sev] += 1

    open_findings = [f for f in findings if _status_display(f.status) not in CLOSED]
    open_count = len(open_findings)

    return {
        "total": total,
        "open": open_count,
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "findings": findings,
    }


def main_sync():
    """Synchronous part: find Excel and load."""
    backend = Path(__file__).resolve().parent.parent
    exports = backend / "data" / "exports"
    if not exports.exists() or not list(exports.glob("*.xlsx")):
        exports = backend.parent / "data" / "exports"

    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path and Path(path).exists():
        path = Path(path)
    else:
        if exports.exists():
            files = sorted(exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
            if files:
                path = files[0]
                print(f"Using latest export: {path.name}\n")
            else:
                path = None
        else:
            path = None

    if not path or not path.exists():
        print("No Excel export found. Run Aikido sync first (VAT_AIKIDO_EXPORT_EXCEL_DIR must be set).")
        return None

    excel_data = load_excel_kamiwaza_develop(path)
    return path, excel_data


async def main():
    result = main_sync()
    if result is None:
        sys.exit(1)
    path, excel_data = result

    print("=" * 80)
    print(f"KAMIWAZA ({BRANCH}) — VAT vs Excel Export Verification")
    print("=" * 80)
    print(f"Excel file: {path}")
    print()

    if not excel_data:
        print("No kamiwaza (develop) rows found in Excel Issues sheet.")
        print("Aikido uses separate repos per branch; repository should be 'kamiwaza (develop)'.")
        print("Run a full Aikido sync to regenerate the export with repo_map enrichment.")
        print()
        print("Proceeding with VAT DB comparison only...")
        excel_data = {"total": 0, "open": 0, "status_counts": {}, "severity_counts": {}}

    async with async_session() as session:
        vat_data = await load_vat_db_kamiwaza_develop(session)

    # Compare
    print("EXCEL (latest export)")
    print("-" * 40)
    print(f"  Total:  {excel_data['total']}")
    print(f"  Open:   {excel_data['open']}")
    print("  Status breakdown:")
    for s, n in sorted(excel_data["status_counts"].items(), key=lambda x: -x[1]):
        print(f"    {s or '(blank)'}: {n}")
    print("  Severity breakdown:")
    for s, n in sorted(excel_data["severity_counts"].items(), key=lambda x: -x[1]):
        print(f"    {s or '(blank)'}: {n}")
    print()

    print("VAT DASHBOARD (DB findings)")
    print("-" * 40)
    print(f"  Total:  {vat_data['total']}")
    print(f"  Open:   {vat_data['open']}")
    print("  Status breakdown:")
    for s, n in sorted(vat_data["status_counts"].items(), key=lambda x: -x[1]):
        print(f"    {s or '(blank)'}: {n}")
    print("  Severity breakdown:")
    for s, n in sorted(vat_data["severity_counts"].items(), key=lambda x: -x[1]):
        print(f"    {s or '(blank)'}: {n}")
    print()

    print("COMPARISON")
    print("-" * 40)
    match_total = excel_data["total"] == vat_data["total"]
    match_open = excel_data["open"] == vat_data["open"]
    print(f"  Total:  Excel={excel_data['total']}  VAT={vat_data['total']}  {'OK' if match_total else 'MISMATCH'}")
    print(f"  Open:   Excel={excel_data['open']}   VAT={vat_data['open']}   {'OK' if match_open else 'MISMATCH'}")

    # Status breakdown comparison
    ex_status = set(excel_data["status_counts"].keys())
    vat_status = set(vat_data["status_counts"].keys())
    status_ok = True
    for s in ex_status | vat_status:
        ex_n = excel_data["status_counts"].get(s, 0)
        vat_n = vat_data["status_counts"].get(s, 0)
        if ex_n != vat_n:
            status_ok = False
            print(f"  Status '{s}': Excel={ex_n}  VAT={vat_n}  MISMATCH")
    if status_ok and (ex_status | vat_status):
        print("  Status breakdown: OK")

    print()
    if excel_data["total"] == 0:
        print("RESULT: Excel has no kamiwaza (develop) data. Run full sync to get branch in export.")
        print("VAT kamiwaza (develop) counts above are from DB for dashboard verification.")
    elif match_total and match_open and status_ok:
        print("RESULT: VAT dashboard data MATCHES the latest Excel export.")
    else:
        print("RESULT: MISMATCH — investigate sync, ingest, or display logic.")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
