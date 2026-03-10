#!/usr/bin/env python3
"""
Simulate full sync ingest using Excel RawIssues — trace where the 34 kamiwaza (develop)
findings are lost without repulling data.

Flow:
1. Load RawIssues from Excel (same data that produced the Issues sheet)
2. Build repo_map from Repos sheet
3. For each raw issue, run adapter.to_vat_finding (same as full sync)
4. Simulate ingest: fingerprint → if exists, merge; else create
5. Count unique findings for kamiwaza (develop) after simulation
6. Report: merge events, fingerprint collisions, order-dependent merges

Run from backend/: uv run python scripts/simulate_excel_to_vat.py [path/to/excel.xlsx]
"""

import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.adapters.aikido import AikidoAdapter, _extract_asset_name, _extract_branch, _parse_repo_name_with_branch
from app.services.dedup import make_fingerprint, make_fingerprint_for_source_issue

ASSET = "kamiwaza"
BRANCH = "develop"


def _normalize_raw_from_excel(d: dict) -> dict:
    """Fix Excel/pandas quirks: float ids, add camelCase aliases for adapter keys."""
    out = dict(d)
    # Fix float ids from pandas (e.g. 105294019.0 -> 105294019)
    for key in ("id", "issue_id", "group_id", "issue_group_id", "code_repo_id"):
        if key in out and out[key] is not None:
            try:
                out[key] = int(float(out[key]))
            except (ValueError, TypeError):
                pass
    # Adapter checks both snake_case and camelCase; pandas lowercases columns
    aliases = [
        ("code_repo_name", "codeRepoName", "codereponame"),
        ("container_repo_name", "containerRepoName", "containerreponame"),
        ("code_repo_id", "codeRepoId", "coderepoid"),
        ("first_detected_at", "firstDetectedAt", "firstdetectedat"),
        ("closed_at", "closedAt", "closedat"),
    ]
    for snake, camel, lower in aliases:
        v = out.get(snake) or out.get(camel) or out.get(lower)
        if v is not None:
            out[snake] = out[camel] = v
    return out


def load_excel(path: Path) -> tuple[list[dict], list[dict]]:
    """Load RawIssues, Issues, and Repos from Excel. Build repo_map from Repos."""
    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        return [], [], {}

    raw_issues = []
    if "RawIssues" in pd.ExcelFile(path).sheet_names:
        df = pd.read_excel(path, sheet_name="RawIssues")
        df = df.rename(columns=lambda c: c.strip().lower().replace(" ", "_") if isinstance(c, str) else c)
        for _, row in df.iterrows():
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
            raw_issues.append(_normalize_raw_from_excel(d))

    issues = []
    df = pd.read_excel(path, sheet_name="Issues")
    df = df.rename(columns=lambda c: c.strip().lower().replace(" ", "_") if isinstance(c, str) else c)
    for _, row in df.iterrows():
        issues.append(dict(row))

    return raw_issues, issues


def infer_repo_from_issues(issues: list[dict]) -> dict[int, tuple[str, str]]:
    """
    Infer issue_id -> (image, branch) from Excel Issues sheet.
    Issues was built with repo_map, so repository='kamiwaza (develop)' is authoritative.
    Use this when we can't fetch repo_map from API (offline simulation).
    """
    out = {}
    for i in issues:
        rid = i.get("issue_id")
        repo = i.get("repository")
        if rid is None or not repo:
            continue
        try:
            rid = int(float(rid))
        except (ValueError, TypeError):
            continue
        repo_str = str(repo).strip()
        if not repo_str or repo_str.lower() == "nan":
            continue
        if rid == 0:
            continue
        base, branch = _parse_repo_name_with_branch(repo_str)
        if base:
            out[rid] = (base, branch or "")
    return out


async def fetch_repo_map() -> dict:
    """Build repo_map from Aikido API if credentials available."""
    repo_map = {}
    try:
        from app.adapters.aikido import fetch_aikido_code_repositories
        from app.core.config import get_settings
        s = get_settings()
        if s.aikido_client_id and s.aikido_client_secret:
            repos = await fetch_aikido_code_repositories()
            for r in repos or []:
                if isinstance(r, dict) and r.get("id") is not None and r.get("branch"):
                    rid = r["id"]
                    repo_map[rid] = str(r["branch"]).strip()
                    repo_map[str(rid)] = str(r["branch"]).strip()
    except Exception:
        pass
    return repo_map


def is_kamiwaza_develop(repo_str) -> bool:
    if not repo_str or (isinstance(repo_str, float) and str(repo_str) == "nan"):
        return False
    s = str(repo_str).strip().lower()
    return (
        s == f"{ASSET.lower()} ({BRANCH.lower()})"
        or f"{ASSET} ({BRANCH})" in s
        or (ASSET.lower() in s and BRANCH.lower() in s)
    )


async def simulate_ingest(
    raw_issues: list[dict],
    repo_map: dict,
    issue_to_repo: dict[int, tuple[str, str]] | None = None,
) -> dict:
    """
    Simulate full sync ingest: process each raw issue in order, compute fingerprint,
    track created vs merged. Returns stats and details for kamiwaza (develop).
    """
    adapter = AikidoAdapter()
    seen_fp: set[str] = set()
    fp_to_first_image_branch: dict[str, tuple[str, str]] = {}

    created = 0
    merged = 0
    kamiwaza_raw_count = 0
    kamiwaza_unique_count = 0
    merge_events: list[dict] = []  # {raw_id, fp, image, branch, merged_into_image_branch}

    for raw in raw_issues:
        if not isinstance(raw, dict):
            continue
        try:
            transformed = await adapter.to_vat_finding(raw, repo_map=repo_map)
        except Exception as e:
            continue

        img = transformed.image or ""
        br = getattr(transformed, "branch", None) or ""
        # Override from Issues sheet when repo_map empty (offline sim)
        if issue_to_repo:
            raw_id = raw.get("id") or raw.get("issue_id")
            if raw_id is not None:
                try:
                    rid = int(float(raw_id))
                    if rid in issue_to_repo:
                        oimg, obr = issue_to_repo[rid]
                        if oimg:
                            img, br = oimg, obr
                except (ValueError, TypeError):
                    pass
        sid = getattr(transformed, "source_issue_id", None)
        tg = getattr(transformed, "tag", None) or ""

        if sid:
            fp = make_fingerprint_for_source_issue("Aikido", str(sid), image=img, branch=br, tag=tg)
        else:
            fp = make_fingerprint(
                transformed.cve_id,
                transformed.component or "",
                image=img,
                branch=br,
                tag=getattr(transformed, "tag", None) or "",
            )

        raw_id = str(raw.get("id") or raw.get("issue_id") or "")
        is_kamiwaza = img == ASSET and br == BRANCH

        if is_kamiwaza:
            kamiwaza_raw_count += 1

        if fp in seen_fp:
            merged += 1
            first_img, first_br = fp_to_first_image_branch.get(fp, ("?", "?"))
            if is_kamiwaza and (first_img != ASSET or first_br != BRANCH):
                merge_events.append({
                    "raw_id": raw_id,
                    "fp_preview": fp[:16] + "...",
                    "image": img,
                    "branch": br,
                    "merged_into": f"{first_img} ({first_br})",
                    "source_issue_id": sid,
                })
            if is_kamiwaza:
                pass  # merged, so no new unique kamiwaza finding
        else:
            seen_fp.add(fp)
            fp_to_first_image_branch[fp] = (img, br)
            created += 1
            if is_kamiwaza:
                kamiwaza_unique_count += 1

    return {
        "created": created,
        "merged": merged,
        "kamiwaza_raw_count": kamiwaza_raw_count,
        "kamiwaza_unique_count": kamiwaza_unique_count,
        "merge_events": merge_events,
        "total_unique": len(seen_fp),
    }


async def main():
    backend = Path(__file__).resolve().parent.parent
    exports = backend / "data" / "exports"
    if not exports.exists():
        exports = backend.parent / "data" / "exports"

    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path and Path(path).exists():
        path = Path(path)
    else:
        files = sorted(exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
        path = files[0] if files else None

    if not path or not path.exists():
        print("No Excel export found. Run Aikido sync first.")
        sys.exit(1)

    print("=" * 80)
    print("SIMULATE: Excel RawIssues → VAT Ingest (kamiwaza develop)")
    print("=" * 80)
    print(f"Excel: {path}\n")

    raw_issues, issues = load_excel(path)
    repo_map = await fetch_repo_map()
    issue_to_repo = infer_repo_from_issues(issues) if not repo_map else None
    excel_kamiwaza = [i for i in issues if is_kamiwaza_develop(i.get("repository", ""))]

    print(f"Excel Issues (kamiwaza develop): {len(excel_kamiwaza)}")
    print(f"RawIssues loaded: {len(raw_issues)}")
    print(f"repo_map entries: {len(repo_map)}")

    if not raw_issues:
        print("\nNo RawIssues in Excel. Cannot simulate.")
        sys.exit(1)

    # Debug: trace one Excel kamiwaza issue through RawIssues → adapter
    sample_raw = None
    if excel_kamiwaza:
        sample_id = excel_kamiwaza[0].get("issue_id")
        if sample_id is not None:
            try:
                sample_id = int(float(sample_id))
            except (ValueError, TypeError):
                sample_id = None
        if sample_id is not None:
            for r in raw_issues:
                rid = r.get("id") or r.get("issue_id")
                if rid is not None:
                    try:
                        if int(float(rid)) == sample_id:
                            sample_raw = r
                            break
                    except (ValueError, TypeError):
                        pass
        if sample_raw:
            adapter = AikidoAdapter()
            try:
                t = await adapter.to_vat_finding(sample_raw, repo_map=repo_map)
                print(f"\n--- DEBUG: Excel issue_id={sample_id} → adapter image={t.image!r} branch={getattr(t,'branch','')!r} ---")
                print(f"  Raw keys (sample): {list(sample_raw.keys())[:20]}...")
                an = _extract_asset_name(sample_raw)
                print(f"  _extract_asset_name(raw)={an!r}")
            except Exception as e:
                print(f"\n--- DEBUG: adapter failed for {sample_id}: {e} ---")

    stats = await simulate_ingest(raw_issues, repo_map, issue_to_repo=issue_to_repo)

    print("\n--- SIMULATION RESULT ---")
    print(f"Total created: {stats['created']}")
    print(f"Total merged:  {stats['merged']}")
    print(f"Total unique findings: {stats['total_unique']}")
    print(f"\nKamiwaza (develop):")
    print(f"  Raw issues mapping to kamiwaza (develop): {stats['kamiwaza_raw_count']}")
    print(f"  Unique findings after ingest: {stats['kamiwaza_unique_count']}")
    print(f"  Lost to merge: {stats['kamiwaza_raw_count'] - stats['kamiwaza_unique_count']}")

    if stats["merge_events"]:
        print(f"\n--- CROSS-REPO MERGE EVENTS ({len(stats['merge_events'])} kamiwaza issues merged into other repos) ---")
        for e in stats["merge_events"][:15]:
            print(f"  raw_id={e['raw_id']} image={e['image']} branch={e['branch']} → merged into {e['merged_into']} (fp={e['fp_preview']})")
        if len(stats["merge_events"]) > 15:
            print(f"  ... and {len(stats['merge_events']) - 15} more")

    print("\n--- COMPARISON ---")
    print(f"  Excel kamiwaza count:  {len(excel_kamiwaza)}")
    print(f"  Simulated VAT count:   {stats['kamiwaza_unique_count']}")
    print(f"  Gap:                   {len(excel_kamiwaza) - stats['kamiwaza_unique_count']}")

    if stats["kamiwaza_raw_count"] != len(excel_kamiwaza):
        print(f"\n  NOTE: RawIssues→kamiwaza ({stats['kamiwaza_raw_count']}) != Issues kamiwaza ({len(excel_kamiwaza)})")
        print("  Possible cause: Excel column/type differences when loading RawIssues.")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
