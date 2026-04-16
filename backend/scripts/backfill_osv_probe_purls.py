"""Backfill missing SBOM purls using OSV probe disambiguation.

This is intentionally conservative:
- probes a small ecosystem set (PyPI/npm/crates.io/NuGet/RubyGems)
- writes purl only when exactly one ecosystem returns vulnerabilities
- marks provenance as derived_probe / medium confidence
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import func, select, text

from app.core.database import async_session
from app.models.sbom import SbomPackage
from app.services.sbom import backfill_purls_via_osv_probe


async def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill SBOM purls via OSV probe.")
    parser.add_argument("--source-name", default="Aikido")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max missing-purl rows to scan (0 = all)",
    )
    args = parser.parse_args()

    source_name = (args.source_name or "").strip()
    source_filter = f"%{source_name}%"

    async with async_session() as db:
        before = await db.scalar(
            select(func.count(SbomPackage.id))
            .where(text("sources::text ILIKE :source_filter"))
            .where(SbomPackage.purl.is_not(None))
            .params(source_filter=source_filter)
        )
        result = await backfill_purls_via_osv_probe(
            db,
            only_source=source_name.lower(),
            limit=max(0, int(args.limit or 0)),
        )
        after = await db.scalar(
            select(func.count(SbomPackage.id))
            .where(text("sources::text ILIKE :source_filter"))
            .where(SbomPackage.purl.is_not(None))
            .params(source_filter=source_filter)
        )

        print(f"source={source_name}")
        print(f"with_purl_before={int(before or 0)}")
        print(f"result={result}")
        print(f"with_purl_after={int(after or 0)}")


if __name__ == "__main__":
    asyncio.run(main())
