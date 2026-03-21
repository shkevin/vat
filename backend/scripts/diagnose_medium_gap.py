#!/usr/bin/env python3
"""
Diagnose why VAT shows 10 open mediums for kamiwaza (develop) vs Aikido's 11.

Searches VAT DB for:
1. All medium findings (open + closed) for kamiwaza (develop)
2. Findings matching the suspected missing ones: Generic API Key, insecure util, js-yaml
3. Medium findings with wrong image/component (mis-grouped under package instead of repo)
4. Raw Aikido data for the missing finding

Run from backend/: uv run python scripts/diagnose_medium_gap.py [path/to/excel.xlsx]
"""

import asyncio
import logging
import sys
from pathlib import Path

logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.finding import Finding

ASSET = "kamiwaza"
BRANCH = "develop"
CLOSED = {
    "Resolved",
    "False Positive",
    "Duplicate",
    "Not Applicable",
    "Approved",
    "Suppressed",
}


def _status_display(s) -> str:
    if s is None:
        return ""
    val = s.value if hasattr(s, "value") else str(s)
    return str(val)


def _get_group_key(f) -> str:
    """Mirror frontend getFindingGroupKey logic for Aikido findings."""
    if f.source == "Aikido" and (f.source_issue_group_id or "").strip():
        return f"aikido:{f.source_issue_group_id.strip()}"
    ft = f.finding_type
    t = (ft.value if hasattr(ft, "value") else str(ft or "")).lower()
    title = (f.title or f.cve_id or f.id or "").lower().strip()
    # SAST/Secret/IaC: include location when available
    path = (f.file_path or "").replace("\\", "/").lstrip("/").lower().strip()
    if path:
        loc = f"{path}@{f.line}" if f.line else path
        return f"n:{t}|{title}|{loc}"
    return f"n:{t}|{title}"


async def query_medium_findings(session: AsyncSession) -> list:
    """All medium findings for kamiwaza (develop)."""
    r = await session.execute(
        select(Finding).where(
            and_(
                Finding.archived == False,
                Finding.source == "Aikido",
                Finding.severity == "Medium",
                Finding.image == ASSET,
                Finding.branch == BRANCH,
            )
        )
    )
    return list(r.scalars().all())


async def query_medium_by_component(
    session: AsyncSession, component_substr: str
) -> list:
    """Medium findings where component contains substring (might be mis-grouped)."""
    r = await session.execute(
        select(Finding).where(
            and_(
                Finding.archived == False,
                Finding.source == "Aikido",
                Finding.severity == "Medium",
                Finding.component.isnot(None),
                Finding.component.ilike(f"%{component_substr}%"),
            )
        )
    )
    return list(r.scalars().all())


async def search_by_title_desc(session: AsyncSession, *keywords: str) -> list:
    """Find findings matching any keyword in title or description."""
    conditions = []
    for kw in keywords:
        conditions.append(Finding.title.ilike(f"%{kw}%"))
        conditions.append(Finding.description.ilike(f"%{kw}%"))
    r = await session.execute(
        select(Finding).where(
            and_(
                Finding.archived == False,
                Finding.source == "Aikido",
                or_(*conditions),
            )
        )
    )
    return list(r.scalars().all())


async def search_by_file_path(session: AsyncSession, *paths: str) -> list:
    """Find findings with file_path containing any of the paths."""
    conditions = [Finding.file_path.ilike(f"%{p}%") for p in paths]
    r = await session.execute(
        select(Finding).where(
            and_(
                Finding.archived == False,
                Finding.source == "Aikido",
                or_(*conditions),
            )
        )
    )
    return list(r.scalars().all())


async def main():
    backend = Path(__file__).resolve().parent.parent
    exports = backend / "data" / "exports"
    if not exports.exists():
        exports = backend.parent / "data" / "exports"

    excel_path = sys.argv[1] if len(sys.argv) > 1 else None
    if excel_path and Path(excel_path).exists():
        excel_path = Path(excel_path)
    else:
        files = sorted(
            exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        excel_path = files[0] if files else None

    print("=" * 80)
    print("VAT vs Aikido — Medium Count Gap Diagnosis (kamiwaza develop)")
    print("=" * 80)

    async with async_session() as session:
        # 1. All medium findings for kamiwaza (develop)
        mediums = await query_medium_findings(session)
        open_mediums = [f for f in mediums if _status_display(f.status) not in CLOSED]

        print("\n1. VAT DB: kamiwaza (develop) MEDIUM findings")
        print(f"   Total: {len(mediums)}, Open: {len(open_mediums)}")

        # Group open mediums by getFindingGroupKey (same as frontend)
        groups: dict[str, list] = {}
        for f in open_mediums:
            key = _get_group_key(f)
            groups.setdefault(key, []).append(f)
        print(f"   Unique groups (VAT display count): {len(groups)}")
        print("\n   Open mediums by group (title | image | component | status):")
        for key, flist in sorted(groups.items(), key=lambda x: (x[1][0].title or "")):
            f = flist[0]
            n = len(flist)
            suffix = f" [{n} instances]" if n > 1 else ""
            print(
                f"     - {key[:50]}... | {f.title[:45]}... | img={f.image} | comp={f.component} | {_status_display(f.status)}{suffix}"
            )

        # 2. Search for suspected missing findings
        print("\n2. Search for 'Generic API Key', 'architecture.md', 'QUICKSTART.md':")
        generic = await search_by_title_desc(
            session, "Generic API Key", "architecture.md", "QUICKSTART.md"
        )
        for f in generic:
            print(
                f"     id={f.id} title={f.title[:50]}... image={f.image} branch={f.branch} comp={f.component} status={_status_display(f.status)}"
            )

        print("\n3. Search for 'insecure util', 'missing input validation':")
        insecure = await search_by_title_desc(
            session, "insecure util", "missing input validation"
        )
        for f in insecure:
            print(
                f"     id={f.id} title={f.title[:50]}... image={f.image} branch={f.branch} comp={f.component} status={_status_display(f.status)}"
            )

        print("\n4. Search for 'js-yaml', 'Prototype Pollution':")
        jsyaml = await search_by_title_desc(session, "js-yaml", "Prototype Pollution")
        for f in jsyaml:
            print(
                f"     id={f.id} title={f.title[:50]}... image={f.image} branch={f.branch} comp={f.component} status={_status_display(f.status)}"
            )

        # 3. Medium findings with image != kamiwaza (might be mis-grouped)
        print(
            "\n5. Aikido medium findings with image != kamiwaza (possible mis-grouping):"
        )
        r = await session.execute(
            select(Finding).where(
                and_(
                    Finding.archived == False,
                    Finding.source == "Aikido",
                    Finding.severity == "Medium",
                    Finding.status == "Open",
                    or_(
                        Finding.image != ASSET,
                        Finding.image.is_(None),
                    ),
                )
            )
        )
        other_mediums = list(r.scalars().all())
        for f in other_mediums[:20]:
            print(
                f"     id={f.id} title={f.title[:50]}... image={f.image} branch={f.branch} comp={f.component}"
            )
        if len(other_mediums) > 20:
            print(f"     ... and {len(other_mediums) - 20} more")

        # 4. File path search for architecture.md, QUICKSTART.md
        print("\n6. Findings in architecture.md or QUICKSTART.md:")
        arch = await search_by_file_path(session, "architecture.md", "QUICKSTART.md")
        for f in arch:
            print(
                f"     id={f.id} title={f.title[:50]}... image={f.image} branch={f.branch} sev={f.severity} status={_status_display(f.status)}"
            )

    # 5. Load Excel and compare
    if excel_path and excel_path.exists():
        try:
            import pandas as pd

            df = pd.read_excel(excel_path, sheet_name="Issues")
            df = df.rename(
                columns=lambda c: c.strip().lower().replace(" ", "_")
                if isinstance(c, str)
                else c
            )
            repo_col = "repository" if "repository" in df.columns else "repository"
            excel_kamiwaza = df[
                (df[repo_col].astype(str).str.lower() == f"{ASSET} ({BRANCH})")
                & (df["severity"].astype(str).str.lower() == "medium")
                & (df["vat_status"].astype(str).str.lower() == "open")
            ]
            print(
                f"\n7. Excel: kamiwaza (develop) open mediums = {len(excel_kamiwaza)}"
            )
            print("   Titles:")
            for _, row in excel_kamiwaza.iterrows():
                print(f"     - {str(row.get('title', ''))[:60]}...")
        except Exception as e:
            print(f"\n7. Could not load Excel: {e}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
