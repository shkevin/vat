#!/usr/bin/env python3
"""
Thorough analysis of VAT finding group aggregation logic per asset.

1. Load ungrouped raw Excel from data/exports
2. Query VAT DB for all findings
3. For each asset (image|branch|tag), compute groups and validate logic
4. Compare with Excel reference (Aikido issue_group_id)
5. Report anomalies, cross-asset leaks, and logical issues

Run: uv run python scripts/grouping_analysis_per_asset.py [path/to/excel.xlsx]
"""

import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path

logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app.core.database import async_session
from app.models.finding import Finding
from app.services.grouping import get_finding_group_key


def _asset_key_from_finding(f: Finding) -> str:
    """Match grouping._asset_key: image|branch|tag."""
    img = (f.image or "").lower().strip()
    br = (f.branch or "").lower().strip()
    tg = (f.tag or "").lower().strip()
    return f"{img}|{br}|{tg}"


def _parse_excel_repo(repo_str: str) -> tuple[str, str | None]:
    """Parse Excel repository like 'kamiwaza (develop)' or 'containers/images/vllm'.

    Container paths (contain /images/) never have branch in name — e.g. whisper-cpp is one token.
    Code repos use 'repo (branch)' or 'repo - branch'.
    """
    import re

    if not repo_str or str(repo_str).lower() == "nan":
        return ("", None)
    s = str(repo_str).strip()
    # Container paths: containers/images/etcd, kamiwaza/images/whisper-cpp — no branch
    if "/images/" in s and s.count("/") >= 2:
        return (s, None)
    # Code repos: "kamiwaza (develop)" or "containers (develop)" — match (branch) only
    m = re.match(r"^(.+?)\s*\(\s*([^)]+)\s*\)\s*$", s)
    if m:
        return (m.group(1).strip(), m.group(2).strip())
    return (s, None)


async def main():
    exports = Path(__file__).resolve().parent.parent.parent / "data" / "exports"
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path and Path(path).exists():
        path = Path(path)
    elif exports.exists():
        files = sorted(
            exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        path = files[0] if files else None

    if not path or not path.exists():
        print("No Excel export found.")
        sys.exit(1)

    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        sys.exit(1)

    df = pd.read_excel(path, sheet_name="Issues")
    df = df.rename(
        columns=lambda c: c.strip().lower().replace(" ", "_")
        if isinstance(c, str)
        else c
    )

    # --- Excel reference ---
    excel_by_asset: dict[str, list] = defaultdict(list)
    for _, row in df.iterrows():
        repo = str(row.get("repository", "") or "").strip()
        if repo.lower() == "nan":
            repo = ""
        base, branch = _parse_excel_repo(repo)
        img = base or ""
        br = (branch or "").lower().strip()
        tg = ""
        asset_key = f"{img}|{br}|{tg}"
        excel_by_asset[asset_key].append(row.to_dict())

    print("=" * 90)
    print("VAT FINDING GROUP AGGREGATION — PER-ASSET ANALYSIS")
    print("=" * 90)
    print(f"Excel: {path.name}")
    print(f"Total Excel issues: {len(df)}")
    print(f"Unique Excel assets (repository): {len(excel_by_asset)}")
    print()

    # --- VAT DB ---
    try:
        async with async_session() as session:
            result = await session.execute(
                select(Finding).where(Finding.archived == False)
            )
            findings = list(result.scalars().all())
    except Exception as e:
        print(f"Could not connect to VAT DB: {e}")
        findings = []

    if not findings:
        print("No findings in VAT DB. Run Aikido sync first.")
        sys.exit(1)

    # Group VAT findings by asset
    vat_by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        ak = _asset_key_from_finding(f)
        vat_by_asset[ak].append(f)

    # Compute groups per asset
    vat_groups_by_asset: dict[str, dict[str, list[Finding]]] = {}
    for asset_key, flist in vat_by_asset.items():
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in flist:
            gk = get_finding_group_key(f)
            groups[gk].append(f)
        vat_groups_by_asset[asset_key] = dict(groups)

    all_assets = sorted(set(vat_by_asset.keys()) | set(excel_by_asset.keys()))
    print(f"Total VAT findings: {len(findings)}")
    print(f"Unique VAT assets: {len(vat_by_asset)}")
    print()

    # --- Per-asset analysis ---
    issues_found: list[str] = []
    for asset_key in all_assets:
        vat_findings = vat_by_asset.get(asset_key, [])
        excel_rows = excel_by_asset.get(asset_key, [])
        vat_groups = vat_groups_by_asset.get(asset_key, {})

        img, br, tg = (asset_key.split("|") + ["", "", ""])[:3]
        display_asset = asset_key.replace("||", " | ").strip("| ") or "(empty)"
        if not display_asset:
            display_asset = "(empty asset)"

        print("-" * 90)
        print(f"ASSET: {display_asset}")
        print(
            f"  image={img or '(none)'}  branch={br or '(none)'}  tag={tg or '(none)'}"
        )
        print(
            f"  VAT findings: {len(vat_findings)}  |  VAT groups: {len(vat_groups)}  |  Excel issues: {len(excel_rows)}"
        )

        if not vat_findings:
            if excel_rows:
                print(
                    "  [NOTE] Excel has issues for this asset but VAT DB has none (sync gap?)"
                )
            continue

        # Group key format check: must end with #asset and suffix must match
        for gk, flist in vat_groups.items():
            if "#" not in gk:
                issues_found.append(
                    f"Asset {display_asset}: group key missing asset suffix: {gk}"
                )
            else:
                suffix = gk.split("#", 1)[1]
                if suffix != asset_key:
                    issues_found.append(
                        f"Asset {display_asset}: group key suffix '{suffix}' != asset '{asset_key}'"
                    )
                # Cross-asset leak: all findings in a group must have same asset
                for f in flist:
                    f_asset = _asset_key_from_finding(f)
                    if f_asset != asset_key:
                        issues_found.append(
                            f"Asset {display_asset}: finding {f.id} in group {gk} has asset {f_asset} (CROSS-ASSET LEAK)"
                        )

        # Type-specific grouping sanity
        ft_counts: dict[str, int] = defaultdict(int)
        for f in vat_findings:
            ft_counts[f.finding_type.value] += 1

        multi_finding_groups = [(k, v) for k, v in vat_groups.items() if len(v) > 1]
        multi_finding_groups.sort(key=lambda x: -len(x[1]))

        if multi_finding_groups:
            print(f"  Groups with 2+ findings: {len(multi_finding_groups)}")
            for gk, flist in multi_finding_groups[:5]:
                sample = flist[0]
                ft = sample.finding_type.value
                if ft == "SCA":
                    pkgs = list(
                        set(f.component_base or f.component or "" for f in flist)
                    )[:3]
                    cves = list(set(f.cve_id for f in flist))[:3]
                    print(
                        f"    {gk}: {len(flist)} findings, pkgs={pkgs}, cves={cves[:3]}..."
                    )
                elif ft == "SAST":
                    rules = list(
                        set(getattr(f, "rule_id", None) or f.title for f in flist)
                    )[:3]
                    print(f"    {gk}: {len(flist)} findings, rules={rules}")
                elif ft == "Secret":
                    print(
                        f"    {gk}: {len(flist)} findings, secret_type={sample.secret_type}"
                    )
                else:
                    print(f"    {gk}: {len(flist)} findings")
        else:
            print("  No groups with multiple findings (all findings are singletons)")

        # SCA empty ecosystem check
        sca_empty = [k for k in vat_groups if k.startswith("sca:|") and "|" in k]
        if sca_empty:
            print(f"  [WARN] SCA groups with empty ecosystem: {len(sca_empty)}")
            for k in sca_empty[:3]:
                print(f"         {k}")

        # Excel vs VAT comparison (when both have data for this asset)
        if excel_rows and vat_findings:
            excel_aikido_groups = len(
                set(str(r.get("issue_group_id", "")) for r in excel_rows)
            )
            print(f"  Excel Aikido groups: {excel_aikido_groups}")
            print(f"  VAT computed groups: {len(vat_groups)}")

        print()

    # --- Summary ---
    print("=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(f"Total assets analyzed: {len(all_assets)}")
    print(f"Total VAT groups: {sum(len(g) for g in vat_groups_by_asset.values())}")
    print(f"Total findings: {len(findings)}")
    print()

    if issues_found:
        print("ISSUES FOUND:")
        for i in issues_found:
            print(f"  - {i}")
    else:
        print(
            "No logical issues detected. Grouping is within-asset; all keys include asset suffix."
        )

    # --- Excel vs VAT overall ---
    print()
    print("EXCEL vs VAT (overall):")
    excel_aikido_groups = len(
        set(str(r.get("issue_group_id", "")) for _, r in df.iterrows())
    )
    vat_total_groups = sum(len(g) for g in vat_groups_by_asset.values())
    print(f"  Excel issues: {len(df)}")
    print(f"  Excel Aikido groups: {excel_aikido_groups}")
    print(f"  VAT findings: {len(findings)}")
    print(f"  VAT computed groups: {vat_total_groups}")
    print()
    print(
        "  Note: VAT groups by ecosystem+package (SCA), rule_id (SAST), etc. Aikido may differ."
    )
    print("  Grouping is scoped within asset (image|branch|tag) per §13.12.")
    print("=" * 90)


if __name__ == "__main__":
    asyncio.run(main())
