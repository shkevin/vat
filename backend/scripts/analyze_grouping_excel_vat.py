#!/usr/bin/env python3
"""
Analyze Excel export vs VAT grouping.

1. Load latest Excel from data/exports
2. Query VAT DB for Aikido findings
3. Compute VAT group keys for each finding
4. Compare group counts and identify mismatches

Run: uv run python scripts/analyze_grouping_excel_vat.py [path/to/excel.xlsx]
"""

import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path

# Suppress SQLAlchemy log spam
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.finding import Finding
from app.services.grouping import get_finding_group_key


def _infer_ecosystem_from_repo(repo: str, pkg: str) -> str:
    """Infer ecosystem from repository/container name. Heuristic for Excel-only analysis."""
    if not repo or str(repo).lower() == "nan":
        return ""
    repo = str(repo).lower()
    pkg = (pkg or "").lower()
    # Container images often have path like kamiwaza/images/vllm -> debian/ubuntu base
    if "images" in repo or "container" in repo:
        return "debian"  # common base for containers
    # Code repos: infer from package name patterns
    if pkg:
        if "." in pkg and not pkg.startswith("org.") and not pkg.startswith("com."):
            return "pypi"  # python-multipart, pdfminer.six
        if pkg.startswith("org.") or pkg.startswith("com.") or "-" in pkg and "java" in pkg:
            return "maven"
        if pkg in ("next.js", "nextjs", "react", "lodash") or pkg.endswith(".js"):
            return "npm"
    return ""


async def main():
    exports = Path(__file__).resolve().parent.parent.parent / "data" / "exports"
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path and Path(path).exists():
        path = Path(path)
    elif exports.exists():
        files = sorted(exports.glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
        path = files[0] if files else None

    if not path or not path.exists():
        print("No Excel export found.")
        sys.exit(1)

    print("=" * 80)
    print("GROUPING ANALYSIS: Excel vs VAT")
    print("=" * 80)
    print(f"Excel: {path.name}\n")

    # Load Excel
    try:
        import pandas as pd
    except ImportError:
        print("pandas required: uv add pandas openpyxl")
        sys.exit(1)

    df = pd.read_excel(path, sheet_name="Issues")
    df = df.rename(columns=lambda c: c.strip().lower().replace(" ", "_") if isinstance(c, str) else c)

    # Excel: Aikido grouping
    aikido_groups = df.groupby("issue_group_id")
    excel_group_count = len(aikido_groups)
    excel_issue_count = len(df)

    print("--- Excel (Aikido) ---")
    print(f"  Total issues: {excel_issue_count}")
    print(f"  Unique issue_group_id (Aikido groups): {excel_group_count}")
    print(f"  Scanner types: {df['scanner_type'].value_counts().to_dict()}")
    print()

    # Simulate VAT group key for each Excel row (for comparison when DB empty)
    def excel_row_to_vat_key(row) -> str:
        st = str(row.get("scanner_type", "")).lower()
        ft = "sca"
        if "sast" in st or "code" in st:
            ft = "sast"
        elif "secret" in st or "leaked" in st:
            ft = "secret"
        elif "iac" in st or "infra" in st:
            ft = "iac"
        elif "license" in st:
            ft = "license"

        pkg = str(row.get("affected_package", "") or "").strip()
        if pkg.lower() == "nan":
            pkg = ""
        cve = str(row.get("cve_id", "") or "").strip()
        if cve.lower() == "nan":
            cve = ""
        repo = str(row.get("repository", "") or "").strip()
        title = str(row.get("title", "") or "").strip()

        if ft == "sca":
            eco = _infer_ecosystem_from_repo(repo, pkg)
            if pkg:
                pkg_norm = pkg.lower().replace("_", "-") if eco == "pypi" else pkg.lower()
                return f"sca:{eco or ''}|{pkg_norm}"
            return f"cve:{cve.lower()}" if cve else f"sca:|{pkg.lower()}"
        if ft == "sast":
            key = title.lower()[:80] if title else cve.lower()
            return f"sast:{key}"
        if ft == "iac":
            key = title.lower()[:80] if title else cve.lower()
            return f"iac:{key}"
        if ft == "secret":
            key = title.lower()[:80] if title else cve.lower()
            return f"secret:{key}"
        if ft == "license":
            eco = _infer_ecosystem_from_repo(repo, pkg)
            pkg_norm = pkg.lower() if pkg else ""
            return f"license:{eco or ''}|{pkg_norm}" if pkg else f"license:{cve}"
        return f"other:{row.get('issue_id', '')}"

    excel_vat_keys = [excel_row_to_vat_key(row) for _, row in df.iterrows()]
    excel_vat_group_count = len(set(excel_vat_keys))

    print("--- Excel with VAT grouping logic (simulated) ---")
    print(f"  Simulated VAT group count: {excel_vat_group_count}")
    print()

    # Query VAT DB
    try:
        async with async_session() as session:
            result = await session.execute(
                select(Finding).where(Finding.archived == False).where(Finding.source == "Aikido")
            )
            findings = list(result.scalars().all())
    except Exception as e:
        print(f"Could not connect to VAT DB: {e}")
        print("(Ensure backend is running and DATABASE_URL is set)")
        findings = []

    if findings:
        print("--- VAT Database ---")
        print(f"  Total Aikido findings in DB: {len(findings)}")

        vat_groups: dict[str, list] = defaultdict(list)
        for f in findings:
            key = get_finding_group_key(f)
            vat_groups[key].append(f)

        vat_group_count = len(vat_groups)
        print(f"  VAT group count (get_finding_group_key): {vat_group_count}")
        print()

        # Sample groups with multiple findings
        multi = [(k, v) for k, v in vat_groups.items() if len(v) > 1]
        multi.sort(key=lambda x: -len(x[1]))
        print("  Top 10 groups by finding count:")
        for key, flist in multi[:10]:
            sevs = [f.severity.value for f in flist]
            pkgs = list(set(f.component_base or f.component or "" for f in flist))[:3]
            print(f"    {key}: {len(flist)} findings, sev={sevs[:3]}...")
        print()

        # Check for potential issues: groups with empty ecosystem
        sca_empty_eco = [k for k in vat_groups if k.startswith("sca:|") and "|" in k]
        if sca_empty_eco:
            print(f"  SCA groups with empty ecosystem (sca:|pkg): {len(sca_empty_eco)}")
            print(f"    Sample: {sca_empty_eco[:5]}")
        print()

        # Compare with Excel
        if excel_issue_count > 0 and len(findings) > 0:
            print("--- Comparison ---")
            print(f"  Excel issues:     {excel_issue_count}")
            print(f"  VAT DB findings: {len(findings)}")
            print(f"  Excel Aikido groups: {excel_group_count}")
            print(f"  VAT computed groups: {vat_group_count}")
            print(f"  Excel simulated VAT groups: {excel_vat_group_count}")
    else:
        print("--- VAT Database ---")
        print("  No Aikido findings in DB.")
        print("  (Run Aikido sync to ingest Excel data into VAT)")
        print()
        print("  Excel simulated VAT group count:", excel_vat_group_count)

    print()
    print("=" * 80)
    print("Expected behavior:")
    print("  - SCA: same package (ecosystem+component_base) = one group")
    print("  - SAST: same rule_id/title = one group")
    print("  - Secret: same secret_type/rule = one group")
    print("  - IaC: same rule_id = one group")
    print("  - VAT group count can differ from Aikido (different grouping logic)")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
