#!/usr/bin/env python3
"""
Diagnose why VAT count differs from Excel (Aikido export).

Modes:
  --all    Compare ALL assets in Excel vs VAT; report matches/mismatches to find bugs.
  (default) Single asset: compare one asset (--asset, --branch).

Run from backend/:
  uv run python scripts/diagnose_vat_excel_gap.py [path] --all
  uv run python scripts/diagnose_vat_excel_gap.py [path] --asset kamiwaza-docs --branch develop
"""

import argparse
import asyncio
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path

logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, and_

from app.adapters.aikido import (
    AikidoAdapter,
    fetch_aikido_code_repositories,
)
from app.core.database import async_session
from app.models.finding import Finding
from app.services.dedup import make_fingerprint, make_fingerprint_for_source_issue


def _parse_repo(repo_str: str) -> tuple[str, str] | None:
    """Parse repository='asset (branch)' e.g. kamiwaza-docs (develop) -> (asset, branch)."""
    if not repo_str or (isinstance(repo_str, float) and str(repo_str) == "nan"):
        return None
    s = str(repo_str).strip()
    if not s:
        return None
    m = re.match(r"^(.+?)\s*\(([^)]+)\)\s*$", s, re.IGNORECASE)
    if m:
        return (m.group(1).strip(), m.group(2).strip())
    return None


def _repo_matches(repo_str: str, asset: str, branch: str) -> bool:
    """Match repository='asset (branch)' e.g. kamiwaza-docs (develop)."""
    parsed = _parse_repo(repo_str)
    if not parsed:
        return False
    a, b = parsed
    return a.lower() == asset.lower() and b.lower() == branch.lower()


def load_excel_raw_and_normalized(path: Path) -> tuple[list[dict], list[dict]]:
    """Load RawIssues and Issues sheets from Excel."""
    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        return [], []

    raw_issues = []
    if "RawIssues" in pd.ExcelFile(path).sheet_names:
        df_raw = pd.read_excel(path, sheet_name="RawIssues")
        df_raw = df_raw.rename(
            columns=lambda c: c.strip().lower().replace(" ", "_")
            if isinstance(c, str)
            else c
        )
        for _, row in df_raw.iterrows():
            d = {}
            for k, v in row.items():
                if pd.isna(v):
                    d[k] = None
                elif isinstance(v, str) and (v.startswith("[") or v.startswith("{")):
                    try:
                        d[k] = json.loads(v)
                    except json.JSONDecodeError:
                        d[k] = v
                else:
                    d[k] = v
            raw_issues.append(d)

    issues = []
    df = pd.read_excel(path, sheet_name="Issues")
    df = df.rename(
        columns=lambda c: c.strip().lower().replace(" ", "_")
        if isinstance(c, str)
        else c
    )
    for _, row in df.iterrows():
        issues.append(dict(row))

    return raw_issues, issues


def _asset_key(asset: str, branch: str) -> tuple[str, str]:
    """Normalize (asset, branch) for consistent dict keys."""
    return (asset.strip().lower(), branch.strip().lower())


async def _run_all_assets_async(path: Path, raw_issues: list, issues: list) -> None:
    """Compare all assets in Excel vs VAT; report matches and mismatches."""
    from app.services.external_links_service import get_source_issue_id

    # 1. Collect all assets from Excel (Issues sheet); use normalized keys
    excel_by_asset: dict[tuple[str, str], list[dict]] = defaultdict(list)
    excel_display: dict[
        tuple[str, str], tuple[str, str]
    ] = {}  # key -> (asset, branch) for display
    for i in issues:
        parsed = _parse_repo(i.get("repository", ""))
        if parsed:
            a, b = parsed
            key = _asset_key(a, b)
            excel_by_asset[key].append(i)
            if key not in excel_display:
                excel_display[key] = (a, b)

    # 2. Collect all assets from VAT DB
    vat_by_asset: dict[tuple[str, str], list] = defaultdict(list)
    vat_display: dict[tuple[str, str], tuple[str, str]] = {}
    async with async_session() as session:
        result = await session.execute(
            select(Finding).where(
                and_(
                    Finding.archived == False,
                    Finding.source == "Aikido",
                )
            )
        )
        for f in result.scalars().all():
            img = f.image or ""
            br = f.branch or ""
            if img or br:
                key = _asset_key(img, br)
                vat_by_asset[key].append(f)
                if key not in vat_display:
                    vat_display[key] = (img, br)

    # 3. Union of all assets; display name from first occurrence
    all_keys = sorted(set(excel_by_asset.keys()) | set(vat_by_asset.keys()))

    print("=" * 90)
    print("VAT vs Excel — ALL ASSETS DIAGNOSIS")
    print("=" * 90)
    print(f"Excel: {path}\n")
    print(
        f"{'Asset':<25} {'Branch':<12} {'Excel':>8} {'VAT':>8} {'Gap':>8} {'Status':<20}"
    )
    print("-" * 90)

    mismatches: list[tuple[tuple[str, str], int, int, int, str]] = []
    for key in all_keys:
        asset, branch = excel_display.get(key) or vat_display.get(key) or key
        excel_list = excel_by_asset.get(key, [])
        vat_list = vat_by_asset.get(key, [])
        excel_ids = {
            str(i.get("issue_id", ""))
            for i in excel_list
            if i.get("issue_id") not in (None, 0, "")
        }
        vat_ids = set()
        for f in vat_list:
            aid = get_source_issue_id(f, "Aikido")
            if aid:
                vat_ids.add(str(aid))

        excel_n = len(excel_list)
        vat_n = len(vat_list)
        gap = excel_n - vat_n

        if key not in excel_by_asset:
            status = "VAT only (not in Excel)"
        elif key not in vat_by_asset:
            status = "Excel only (not in VAT)"
        elif gap > 0 and not (vat_ids - excel_ids):
            status = "Dedup (expected)"
        elif vat_ids - excel_ids:
            status = "BUG: VAT has unknown IDs"
        elif gap < 0:
            status = "BUG: VAT > Excel"
        elif gap == 0 and excel_ids != vat_ids:
            status = "Different IDs (check)"
        else:
            status = "Match"

        if (
            "BUG" in status
            or "Excel only" in status
            or "VAT only" in status
            or "Different" in status
        ):
            mismatches.append(((asset, branch), excel_n, vat_n, gap, status))

        print(f"{asset:<25} {branch:<12} {excel_n:>8} {vat_n:>8} {gap:>8} {status:<20}")

    print("-" * 90)
    print(f"\nTotal assets: {len(all_keys)}")
    if mismatches:
        print(f"\n--- POTENTIAL BUGS ({len(mismatches)} assets) ---")
        for (asset, branch), ex, vat, gap, status in mismatches:
            print(f"  {asset} ({branch}): Excel={ex}, VAT={vat}, gap={gap} — {status}")
    else:
        print("\nAll assets match (gaps are from deduplication, which is expected).")


def _normalize_sev(s: str) -> str:
    """Normalize severity for comparison (Excel/Aikido vs VAT model)."""
    if not s:
        return "medium"
    x = str(s).lower().strip()
    for k in ("critical", "high", "medium", "low", "info", "informational"):
        if k in x:
            return "informational" if "info" in k else k
    return "medium"


def _severity_rank(sev: str) -> int:
    """Higher = more severe. For comparing max."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    return order.get(_normalize_sev(sev), 2)


async def _print_severity_comparison(
    excel_issues: list[dict],
    vat_findings: list,
    raw_by_id: dict[str, dict],
    adapter: "AikidoAdapter",
    repo_map: dict,
    repo_id_to_name: dict,
    asset: str,
    branch: str,
) -> None:
    """Compare Excel (Aikido) severity vs VAT severity per fingerprint. Report mismatches."""
    from app.services.external_links_service import get_source_issue_id

    # Build fp -> list of (issue_id, excel_severity) from Excel
    excel_fp_to_items: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for i in excel_issues:
        oid = str(i.get("issue_id", "") or "")
        if not oid or oid in ("0", "nan", "None"):
            continue
        raw = raw_by_id.get(oid)
        if not raw:
            continue
        try:
            t = await adapter.to_vat_finding(
                raw, repo_map=repo_map, repo_id_to_name=repo_id_to_name
            )
        except Exception:
            continue
        fp = make_fingerprint(
            t.cve_id,
            t.component or "",
            image=t.image or "",
            branch=getattr(t, "branch", None) or "",
            tag=getattr(t, "tag", None) or "",
        )
        if (t.image or "") == asset and (getattr(t, "branch", None) or "") == branch:
            excel_sev = _normalize_sev(str(i.get("severity", "medium") or "medium"))
            excel_fp_to_items[fp].append((oid, excel_sev))

    # Build fp -> VAT finding
    vat_fp_to_finding: dict[str, object] = {}
    for f in vat_findings:
        aid = get_source_issue_id(f, "Aikido")
        if f.fingerprint_id:
            vat_fp_to_finding[f.fingerprint_id] = f

    mismatches = []
    for fp, items in excel_fp_to_items.items():
        vat_f = vat_fp_to_finding.get(fp)
        if not vat_f:
            continue
        vat_sev = _normalize_sev(vat_f.severity.value if vat_f.severity else "medium")
        excel_sevs = [sev for _, sev in items]
        max_excel = max(excel_sevs, key=_severity_rank)
        if vat_sev != max_excel:
            mismatches.append(
                (fp[:16], vat_sev, max_excel, items, vat_f.cve_id, vat_f.component)
            )

    if mismatches:
        print(f"Found {len(mismatches)} severity mismatch(es):")
        for fp, vat_sev, max_excel, items, cve, comp in mismatches[:15]:
            print(f"  fp={fp}... cve={cve} comp={comp}")
            print(f"    Excel/Aikido: {dict(items)} | max={max_excel}")
            print(f"    VAT:          {vat_sev}")
            print("    -> BUG: merge kept first severity; should use max")
    else:
        print("No severity mismatches (Excel vs VAT aligned).")


async def _run_single_asset_async(
    path: Path,
    asset: str,
    branch: str,
    raw_issues: list,
    issues: list,
) -> None:
    """Single-asset diagnosis: compare Excel vs VAT for one asset (branch)."""
    from app.services.external_links_service import get_source_issue_id

    excel_filtered = [
        i for i in issues if _repo_matches(i.get("repository", ""), asset, branch)
    ]
    excel_issue_ids = {
        str(i.get("issue_id", ""))
        for i in excel_filtered
        if i.get("issue_id") not in (None, 0, "")
    }

    async with async_session() as session:
        result = await session.execute(
            select(Finding).where(
                and_(
                    Finding.archived == False,
                    Finding.source == "Aikido",
                    Finding.image == asset,
                    Finding.branch == branch,
                )
            )
        )
        vat_findings = list(result.scalars().all())

    vat_issue_ids = set()
    for f in vat_findings:
        aid = get_source_issue_id(f, "Aikido")
        if aid:
            vat_issue_ids.add(str(aid))

    in_excel_not_vat = excel_issue_ids - vat_issue_ids
    in_vat_not_excel = vat_issue_ids - excel_issue_ids

    print("=" * 80)
    print(f"VAT vs Excel Gap Diagnosis — {asset} ({branch})")
    print("=" * 80)
    print(f"Excel: {path}\n")
    print(f"Excel Issues ({asset} {branch}): {len(excel_filtered)}")
    print(f"VAT findings ({asset} {branch}): {len(vat_findings)}")
    print(f"\nIn Excel but NOT in VAT: {len(in_excel_not_vat)}")
    print(f"In VAT but NOT in Excel: {len(in_vat_not_excel)}")

    if in_excel_not_vat and not in_vat_not_excel:
        print("\n--- ROOT CAUSE: Deduplication ---")
        print(
            f"Excel: {len(excel_filtered)} issues (Aikido shows 1 row per issue instance)"
        )
        print(
            f"VAT:   {len(vat_findings)} findings (1 row per unique CVE+component+image+branch)"
        )
        print(
            f"Gap:   {len(in_excel_not_vat)} Aikido issues were merged into VAT findings (same fingerprint)"
        )

    if raw_issues:
        repo_map = {}
        try:
            from app.core.config import get_settings

            s = get_settings()
            if s.aikido_client_id and s.aikido_client_secret:
                repos = await fetch_aikido_code_repositories()
                for r in repos or []:
                    if (
                        isinstance(r, dict)
                        and r.get("id") is not None
                        and r.get("branch")
                    ):
                        rid = r["id"]
                        repo_map[rid] = str(r["branch"]).strip()
                        repo_map[str(rid)] = str(r["branch"]).strip()
        except Exception as e:
            print(f"Could not fetch repo_map: {e}")

        adapter = AikidoAdapter()
        fp_to_raw_ids: dict[str, list[str]] = defaultdict(list)
        no_source_id: list[dict] = []
        target_raw: list[dict] = []

        for raw in raw_issues:
            if not isinstance(raw, dict):
                continue
            try:
                transformed = await adapter.to_vat_finding(raw, repo_map=repo_map)
            except Exception as e:
                print(f"  Adapter failed for raw id={raw.get('id')}: {e}")
                continue

            rid = str(raw.get("id") or raw.get("issue_id") or "")
            sid = getattr(transformed, "source_issue_id", None)
            img = transformed.image or ""
            br = getattr(transformed, "branch", None) or ""

            if img == asset and br == branch:
                target_raw.append(raw)

            if not sid:
                no_source_id.append(
                    {
                        "raw_id": rid,
                        "image": img,
                        "branch": br,
                        "cve": transformed.cve_id,
                    }
                )

            tg = getattr(transformed, "tag", None) or ""
            if sid:
                fp = make_fingerprint_for_source_issue(
                    "Aikido", str(sid), image=img, branch=br, tag=tg
                )
            else:
                fp = make_fingerprint(
                    transformed.cve_id,
                    transformed.component or "",
                    image=img,
                    branch=br,
                    tag=getattr(transformed, "tag", None) or "",
                )
            fp_to_raw_ids[fp].append(rid)

        collisions = {fp: ids for fp, ids in fp_to_raw_ids.items() if len(ids) > 1}
        print("\n--- Simulated ingest (from RawIssues) ---")
        print(f"Raw issues mapping to {asset} ({branch}): {len(target_raw)}")
        print(f"Fingerprint collisions (same fp, multiple raw ids): {len(collisions)}")

        if collisions:
            total_collapsed = sum(len(ids) - 1 for ids in collisions.values())
            print(f"  Total 'lost' to merge: {total_collapsed}")

        raw_by_id = {
            str(r.get("id") or r.get("issue_id", "")): r
            for r in raw_issues
            if r.get("id") or r.get("issue_id")
        }
        repo_id_to_name = {}
        try:
            repos = await fetch_aikido_code_repositories()
            for r in repos or []:
                if isinstance(r, dict) and r.get("id") is not None and r.get("name"):
                    rid = r["id"]
                    repo_id_to_name[rid] = str(r["name"]).strip()
                    repo_id_to_name[str(rid)] = str(r["name"]).strip()
        except Exception:
            pass
        print("\n--- Severity comparison (Excel/Aikido vs VAT) ---")
        await _print_severity_comparison(
            excel_filtered,
            vat_findings,
            raw_by_id,
            adapter,
            repo_map,
            repo_id_to_name,
            asset,
            branch,
        )
        print("\n--- Missing from VAT (sample) ---")
        for oid in list(in_excel_not_vat)[:10]:
            r = raw_by_id.get(oid)
            if r:
                try:
                    t = await adapter.to_vat_finding(r, repo_map=repo_map)
                    print(
                        f"  issue_id={oid}: image={t.image}, branch={getattr(t,'branch','')}"
                    )
                except Exception as e:
                    print(f"  issue_id={oid}: adapter error {e}")
            else:
                print(f"  issue_id={oid}: not in RawIssues")

    print("\n" + "=" * 80)


async def main():
    parser = argparse.ArgumentParser(description="Diagnose VAT vs Excel gap")
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to aikido_sync_*.xlsx (default: latest in data/exports)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Compare ALL assets in Excel vs VAT"
    )
    parser.add_argument(
        "--asset", default="kamiwaza-docs", help="Asset name (single-asset mode)"
    )
    parser.add_argument(
        "--branch", default="develop", help="Branch (single-asset mode)"
    )
    args = parser.parse_args()

    backend = Path(__file__).resolve().parent.parent
    exports = backend / "data" / "exports"
    if not exports.exists():
        exports = backend.parent / "data" / "exports"

    path = Path(args.path) if args.path and Path(args.path).exists() else None
    if not path:
        files = sorted(
            exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        path = files[0] if files else None

    if not path or not path.exists():
        print("No Excel export found. Run Aikido sync first.")
        sys.exit(1)

    raw_issues, issues = load_excel_raw_and_normalized(path)

    if args.all:
        await _run_all_assets_async(path, raw_issues, issues)
    else:
        await _run_single_asset_async(path, args.asset, args.branch, raw_issues, issues)


if __name__ == "__main__":
    asyncio.run(main())
