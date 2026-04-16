"""Diagnose SBOM -> OSV matching coverage and blind spots.

Read-only script:
- Reports purl coverage/provenance for Aikido-ingested SBOM rows
- Explains why rows are still missing purl (rule coverage buckets)
- Probes OSV query/match hit rates using current matcher logic
"""

from __future__ import annotations

import argparse
import asyncio
import re
from collections import Counter
from typing import Iterable

import httpx
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.database import async_session
from app.models.sbom import SbomPackage
from app.models.vuln_feed_record import VulnFeedRecord
from app.services.vuln_feeds import _sbom_osv_target


def _reason_bucket(name: str | None, version: str | None, language: str | None) -> str:
    pkg = (name or "").strip()
    ver = (version or "").strip()
    lang = (language or "").strip().lower()
    if not pkg:
        return "missing_name"
    if not ver:
        return "missing_version"
    if lang:
        return "language_present_but_unmapped"
    if ver.endswith(tuple(f"-r{i}" for i in range(10))):
        return "alpine_like_version_suffix"
    if pkg.startswith(("github.com/", "golang.org/", "gopkg.in/")):
        return "go_like_supported_prefix"
    if pkg.startswith("@") and "/" in pkg:
        return "npm_scoped"
    if ":" in pkg and "." in pkg.split(":", 1)[0]:
        return "maven_like"
    if re.match(r"^[a-z0-9_.-]+$", pkg):
        return "generic_package_name_no_ecosystem_signal"
    if "/" in pkg and "." in pkg.split("/", 1)[0]:
        return "go_like_other_domain_prefix"
    return "other_unclassified"


def _top_prefixes(values: Iterable[str], limit: int = 20) -> list[tuple[str, int]]:
    c = Counter()
    for value in values:
        p = (value or "").split("/", 1)[0].strip().lower()
        if p:
            c[p] += 1
    return c.most_common(limit)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose SBOM -> OSV matching coverage.")
    parser.add_argument(
        "--source-name",
        default="Aikido",
        help="SBOM source name to scope diagnosis (default: Aikido)",
    )
    parser.add_argument(
        "--probe-limit",
        type=int,
        default=500,
        help="How many SBOM packages to include in OSV probe (default: 500)",
    )
    parser.add_argument(
        "--window-count",
        type=int,
        default=5,
        help="How many refresh-like windows to sample (default: 5)",
    )
    args = parser.parse_args()

    source_name = (args.source_name or "").strip()
    if not source_name:
        raise SystemExit("--source-name must be non-empty")

    source_filter = f"%{source_name}%"

    async with async_session() as db:
        total = await db.scalar(
            select(func.count(SbomPackage.id)).where(
                text("sources::text ILIKE :source_filter")
            ).params(source_filter=source_filter)
        )
        with_purl = await db.scalar(
            select(func.count(SbomPackage.id))
            .where(text("sources::text ILIKE :source_filter"))
            .where(SbomPackage.purl.is_not(None))
            .params(source_filter=source_filter)
        )
        with_lang = await db.scalar(
            select(func.count(SbomPackage.id))
            .where(text("sources::text ILIKE :source_filter"))
            .where(SbomPackage.language.is_not(None))
            .params(source_filter=source_filter)
        )

        print(f"## Source: {source_name}")
        print(f"sbom_total={int(total or 0)}")
        print(f"sbom_with_purl={int(with_purl or 0)}")
        print(f"sbom_with_language={int(with_lang or 0)}")

        by_provenance = (
            await db.execute(
                select(
                    SbomPackage.purl_source,
                    SbomPackage.purl_confidence,
                    func.count(SbomPackage.id),
                )
                .where(text("sources::text ILIKE :source_filter"))
                .where(SbomPackage.purl.is_not(None))
                .group_by(SbomPackage.purl_source, SbomPackage.purl_confidence)
                .order_by(func.count(SbomPackage.id).desc())
                .params(source_filter=source_filter)
            )
        ).all()
        print("\n## PURL Provenance")
        for row in by_provenance:
            print(
                f"purl_source={row[0] or 'null'} purl_confidence={row[1] or 'null'} count={int(row[2] or 0)}"
            )
        if not by_provenance:
            print("none")

        no_purl_rows = (
            await db.execute(
                select(SbomPackage.name, SbomPackage.version, SbomPackage.language)
                .where(text("sources::text ILIKE :source_filter"))
                .where(SbomPackage.purl.is_(None))
                .params(source_filter=source_filter)
            )
        ).all()
        reason_counts = Counter(
            _reason_bucket(name, version, language)
            for name, version, language in no_purl_rows
        )
        print("\n## Missing-PURL Reason Buckets")
        for reason, count in reason_counts.most_common():
            print(f"{reason}={count}")
        if not reason_counts:
            print("none")

        go_other_domains = [
            (name or "")
            for name, version, language in no_purl_rows
            if _reason_bucket(name, version, language) == "go_like_other_domain_prefix"
        ]
        if go_other_domains:
            print("\n## Top Go-Like Unhandled Prefixes")
            for prefix, count in _top_prefixes(go_other_domains, limit=20):
                print(f"{prefix}={count}")

        probe_rows = (
            await db.execute(
                select(
                    SbomPackage.name,
                    SbomPackage.version,
                    SbomPackage.language,
                    SbomPackage.purl,
                )
                .where(text("sources::text ILIKE :source_filter"))
                .order_by(SbomPackage.updated_at.desc())
                .limit(max(1, args.probe_limit))
                .params(source_filter=source_filter)
            )
        ).all()
        queries: list[dict] = []
        for name, version, language, purl in probe_rows:
            target = _sbom_osv_target(
                name=name, version=version, language=language, purl=purl
            )
            if not target:
                continue
            package_name, ecosystem = target
            queries.append(
                {"package": {"name": package_name, "ecosystem": ecosystem}, "version": version}
            )

        settings = get_settings()
        timeout = httpx.Timeout(settings.vuln_feed_request_timeout_sec)
        headers = {"User-Agent": settings.vuln_feed_user_agent}

        vuln_count = 0
        matched_query_rows = 0
        if queries:
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
                resp = await client.post(
                    "https://api.osv.dev/v1/querybatch", json={"queries": queries}
                )
                resp.raise_for_status()
                payload = resp.json()
            results = payload.get("results") if isinstance(payload, dict) else []
            if isinstance(results, list):
                for row in results:
                    if not isinstance(row, dict):
                        continue
                    vulns = row.get("vulns")
                    if isinstance(vulns, list) and vulns:
                        matched_query_rows += 1
                        vuln_count += len(vulns)

        print("\n## OSV Probe")
        print(f"input_rows={len(probe_rows)}")
        print(f"query_count={len(queries)}")
        print(f"vuln_count={vuln_count}")
        print(f"matched_query_rows={matched_query_rows}")

        # Simulate deterministic refresh windows to explain cursor behavior.
        max_queries = max(1, int(settings.vuln_feed_osv_max_queries or 200))
        window_rows = (
            await db.execute(
                select(
                    SbomPackage.name,
                    SbomPackage.version,
                    SbomPackage.language,
                    SbomPackage.purl,
                )
                .where(text("sources::text ILIKE :source_filter"))
                .where(SbomPackage.name.is_not(None), SbomPackage.version.is_not(None))
                .order_by(
                    func.coalesce(SbomPackage.tenant_id, ""),
                    func.coalesce(SbomPackage.component, ""),
                    func.lower(SbomPackage.name),
                    func.coalesce(SbomPackage.version, ""),
                )
                .limit(max_queries * max(1, args.window_count))
                .params(source_filter=source_filter)
            )
        ).all()
        print("\n## Refresh Window Simulation")
        print(f"window_size={max_queries} sample_windows={max(1, args.window_count)}")
        if window_rows:
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
                for window_idx in range(max(1, args.window_count)):
                    start = window_idx * max_queries
                    chunk = window_rows[start : start + max_queries]
                    if not chunk:
                        break
                    chunk_queries: list[dict] = []
                    for name, version, language, purl in chunk:
                        target = _sbom_osv_target(
                            name=name, version=version, language=language, purl=purl
                        )
                        if not target:
                            continue
                        package_name, ecosystem = target
                        chunk_queries.append(
                            {
                                "package": {"name": package_name, "ecosystem": ecosystem},
                                "version": version,
                            }
                        )
                    if not chunk_queries:
                        print(
                            f"window={window_idx} query_count=0 vuln_count=0 matched_rows=0"
                        )
                        continue
                    resp = await client.post(
                        "https://api.osv.dev/v1/querybatch", json={"queries": chunk_queries}
                    )
                    resp.raise_for_status()
                    payload = resp.json()
                    results = payload.get("results") if isinstance(payload, dict) else []
                    win_vulns = 0
                    win_matches = 0
                    if isinstance(results, list):
                        for row in results:
                            if not isinstance(row, dict):
                                continue
                            vulns = row.get("vulns")
                            if isinstance(vulns, list) and vulns:
                                win_matches += 1
                                win_vulns += len(vulns)
                    print(
                        f"window={window_idx} query_count={len(chunk_queries)} "
                        f"vuln_count={win_vulns} matched_rows={win_matches}"
                    )

        osv_record_count = await db.scalar(
            select(func.count(VulnFeedRecord.id)).where(VulnFeedRecord.source == "osv")
        )
        print("\n## Stored OSV Records")
        print(f"osv_record_count={int(osv_record_count or 0)}")

        sample_rows = (
            await db.execute(
                select(
                    SbomPackage.name,
                    SbomPackage.version,
                    SbomPackage.language,
                    SbomPackage.purl,
                    SbomPackage.purl_source,
                    SbomPackage.purl_confidence,
                )
                .where(text("sources::text ILIKE :source_filter"))
                .order_by(SbomPackage.updated_at.desc())
                .limit(25)
                .params(source_filter=source_filter)
            )
        ).all()
        print("\n## Recent SBOM Samples")
        for row in sample_rows:
            print(row)

        # Coverage from current OSV target resolver (purl-first + fallback).
        targetable = 0
        for name, version, language, purl, *_ in sample_rows:
            if _sbom_osv_target(
                name=name, version=version, language=language, purl=purl
            ):
                targetable += 1
        print("\n## Recent Sample Targetability")
        print(f"targetable_recent_rows={targetable}/{len(sample_rows)}")


if __name__ == "__main__":
    asyncio.run(main())
