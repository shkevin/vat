#!/usr/bin/env python3
"""Create isolated SBOM/feed correlation fixtures and verify materialized findings.

Usage examples:
  uv run python backend/scripts/create_feed_correlation_fixtures.py
  uv run python backend/scripts/create_feed_correlation_fixtures.py --package axios --limit 8
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from sqlalchemy import desc, func, select

# Ensure `app` imports work whether script is run from repo root or backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.database import async_session
from app.models.asset_alias import AssetAlias
from app.models.finding import Finding
from app.models.sbom import SbomPackage
from app.models.vuln_feed_record import VulnFeedRecord
from app.services.vuln_feeds import SOURCE_VULN_FEED_MATCH, materialize_feed_matches_to_findings

VERIFY_TENANT = "feed-verify"
VERIFY_PREFIX = "asset-feed-verify"
DEMO_SOURCE = "fixture_demo"


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_id(seed: str, prefix: str, size: int = 16) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:size]
    return f"{prefix}-{digest}"


def _guess_language(ecosystem: str | None) -> str:
    eco = (ecosystem or "").strip().lower()
    if eco == "pypi":
        return "python"
    if eco in {"npm", "node"}:
        return "javascript"
    if eco == "go":
        return "go"
    if eco == "maven":
        return "java"
    if eco == "rubygems":
        return "ruby"
    if eco == "crates.io":
        return "rust"
    if eco in {"debian", "ubuntu", "alpine", "rpm"}:
        return eco
    return "python"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--package",
        default="axios",
        help="Package name to prioritize when creating fixtures (default: axios).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=6,
        help="Max advisories to use for fixture SBOM rows (default: 6).",
    )
    p.add_argument(
        "--include-any",
        action="store_true",
        help="If preferred package has too few advisories, include other recent advisories.",
    )
    p.add_argument(
        "--allow-versionless",
        action="store_true",
        help="Allow advisories with no version (can produce broad match sets).",
    )
    p.add_argument(
        "--no-demo-if-missing",
        action="store_true",
        help="Do not create synthetic demo advisories when pulled feed data has no matches.",
    )
    return p.parse_args()


async def _cleanup_previous_fixtures() -> None:
    async with async_session() as db:
        findings = (
            (
                await db.execute(
                    select(Finding).where(
                        Finding.source == SOURCE_VULN_FEED_MATCH,
                        Finding.tenant_id == VERIFY_TENANT,
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in findings:
            await db.delete(row)

        sbom_rows = (
            (
                await db.execute(
                    select(SbomPackage).where(SbomPackage.tenant_id == VERIFY_TENANT)
                )
            )
            .scalars()
            .all()
        )
        for row in sbom_rows:
            await db.delete(row)

        alias_rows = (
            (
                await db.execute(
                    select(AssetAlias).where(
                        AssetAlias.source_asset_id.like(f"{VERIFY_PREFIX}%")
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in alias_rows:
            await db.delete(row)

        await db.commit()
    async with async_session() as db:
        demo_rows = (
            (
                await db.execute(
                    select(VulnFeedRecord).where(VulnFeedRecord.source == DEMO_SOURCE)
                )
            )
            .scalars()
            .all()
        )
        for row in demo_rows:
            await db.delete(row)
        await db.commit()


async def _create_demo_advisories(package: str, limit: int) -> list[VulnFeedRecord]:
    pkg = (package or "").strip().lower() or "axios"
    now = datetime.utcnow()
    demo_versions = ["1.7.7", "1.7.9", "1.8.0"]
    advisories: list[VulnFeedRecord] = []
    async with async_session() as db:
        for idx, ver in enumerate(demo_versions[: max(1, limit)]):
            vuln_id = f"CVE-2099-AX{idx + 1:03d}"
            rec = VulnFeedRecord(
                source=DEMO_SOURCE,
                record_key=f"{vuln_id}|{pkg}|npm|{ver}",
                vulnerability_id=vuln_id,
                aliases=[vuln_id],
                package_name=pkg,
                ecosystem="npm",
                version=ver,
                severity="HIGH" if idx == 0 else "MEDIUM",
                title=f"Demo advisory for {pkg} {ver}",
                details={
                    "description": f"Synthetic advisory for {pkg} {ver} used to verify SBOM/feed materialization.",
                    "severity": "high" if idx == 0 else "medium",
                },
                published_at=now,
                modified_at=now,
                fetched_at=now,
                run_id="fixture-feed-verify",
            )
            db.add(rec)
            advisories.append(rec)
        await db.commit()
    return advisories


async def _select_candidate_advisories(
    preferred_package: str, limit: int, include_any: bool, allow_versionless: bool
) -> list[VulnFeedRecord]:
    preferred = preferred_package.strip().lower()
    if not preferred:
        return []
    async with async_session() as db:
        preferred_query = select(VulnFeedRecord).where(
            func.lower(VulnFeedRecord.package_name) == preferred
        )
        if not allow_versionless:
            preferred_query = preferred_query.where(VulnFeedRecord.version.is_not(None))
        preferred_query = preferred_query.order_by(
            desc(VulnFeedRecord.fetched_at), desc(VulnFeedRecord.id)
        ).limit(max(1, limit))
        preferred_rows = ((await db.execute(preferred_query)).scalars().all())
        if len(preferred_rows) >= limit or not include_any:
            return preferred_rows

        remaining = max(0, limit - len(preferred_rows))
        extra_query = (
            select(VulnFeedRecord)
            .where(VulnFeedRecord.package_name.is_not(None))
            .where(func.lower(VulnFeedRecord.package_name) != preferred)
        )
        if not allow_versionless:
            extra_query = extra_query.where(VulnFeedRecord.version.is_not(None))
        extra_query = extra_query.order_by(
            desc(VulnFeedRecord.fetched_at), desc(VulnFeedRecord.id)
        ).limit(remaining)
        extra_rows = (await db.execute(extra_query)).scalars().all()
        return [*preferred_rows, *extra_rows]


def _sbom_rows_for_advisories(
    rows: Sequence[VulnFeedRecord], allow_versionless: bool
) -> tuple[list[SbomPackage], list[AssetAlias]]:
    sbom_rows: list[SbomPackage] = []
    alias_rows: list[AssetAlias] = []
    canonical_asset = f"{VERIFY_PREFIX}-canonical"
    for idx, adv in enumerate(rows):
        pkg_name = (adv.package_name or "").strip()
        if not pkg_name:
            continue
        version = (adv.version or "").strip()
        if not version and not allow_versionless:
            continue
        version = version or "0.0.0-test"
        source_asset = f"{VERIFY_PREFIX}-{idx + 1}"
        component = source_asset
        if idx == 0:
            component = f"{VERIFY_PREFIX}-alias-1"
            alias_rows.append(
                AssetAlias(
                    source_asset_id=component,
                    canonical_asset_id=canonical_asset,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
            )
        sbom_rows.append(
            SbomPackage(
                id=_safe_id(f"{pkg_name}|{version}|{component}", "sbomvf"),
                name=pkg_name,
                version=version,
                component=component,
                language=_guess_language(adv.ecosystem),
                sources=[{"name": "feed-fixture", "importedAt": _now_iso()}],
                tenant_id=VERIFY_TENANT,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )
    return sbom_rows, alias_rows


async def _create_and_verify(
    preferred_package: str,
    limit: int,
    include_any: bool,
    allow_versionless: bool,
    create_demo_if_missing: bool,
) -> int:
    advisories = await _select_candidate_advisories(
        preferred_package, limit, include_any, allow_versionless
    )
    if not advisories and create_demo_if_missing:
        advisories = await _create_demo_advisories(preferred_package, min(limit, 3))
        print(
            f"No matching pulled advisories found for '{preferred_package}'. "
            f"Created {len(advisories)} synthetic demo advisories instead."
        )
    if not advisories:
        print("No advisories found in vuln_feed_records for requested package/filter.")
        print("Tip: run a feed refresh first, or omit --no-demo-if-missing.")
        return 1

    sbom_rows, alias_rows = _sbom_rows_for_advisories(advisories, allow_versionless)
    if not sbom_rows:
        print("No SBOM fixture rows generated (advisories lacked package names).")
        return 1

    async with async_session() as db:
        for row in alias_rows:
            db.add(row)
        for row in sbom_rows:
            db.add(row)
        await db.flush()

        result = await materialize_feed_matches_to_findings(
            db, trace_id="trace-feed-fixture", actor_id="feed-fixture-script"
        )
        await db.commit()

        findings = (
            (
                await db.execute(
                    select(Finding)
                    .where(
                        Finding.source == SOURCE_VULN_FEED_MATCH,
                        Finding.tenant_id == VERIFY_TENANT,
                    )
                    .order_by(desc(Finding.created_at))
                )
            )
            .scalars()
            .all()
        )

    print("\n=== Feed/SBOM Materialization Verification ===")
    print(f"Preferred package: {preferred_package}")
    print(f"Fixture SBOM rows: {len(sbom_rows)}")
    print(f"Materialization result: {result}")
    print(f"Materialized findings (tenant={VERIFY_TENANT}): {len(findings)}")
    for f in findings[:20]:
        print(
            f"- {f.cve_id} | sev={f.severity.value} | status={f.status.value} | "
            f"asset={f.image} | pkg={f.component_base} | conf={f.correlation_confidence} | key={f.correlation_key}"
        )
    print("\nFixture tenant is isolated; rerun script to refresh fixtures.")
    return 0


async def _run() -> int:
    args = _parse_args()
    await _cleanup_previous_fixtures()
    return await _create_and_verify(
        preferred_package=args.package,
        limit=max(1, args.limit),
        include_any=bool(args.include_any),
        allow_versionless=bool(args.allow_versionless),
        create_demo_if_missing=not bool(args.no_demo_if_missing),
    )


def main() -> None:
    code = asyncio.run(_run())
    raise SystemExit(code)


if __name__ == "__main__":
    main()
