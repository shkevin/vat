"""Known image-digest projection — dedup source of truth for event-driven scans.

The operator warms its in-memory dedup set from this so it never re-scans a digest
VAT already has data for. Read-only over the two places VAT persists a resolved
manifest digest: ``findings.image_digest`` and ``asset_observed_tags.last_digest``.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding
from app.parsers.image_digest import normalize_image_digest


async def known_image_digests(db: AsyncSession) -> list[str]:
    """Distinct, normalized ``sha256:…`` digests VAT already has data for, sorted.

    Two DISTINCT scans + a Python set rather than a SQL UNION: normalization
    (lowercasing, stripping junk) has to happen in Python anyway, so the set does
    the cross-table dedup. Cardinality is hundreds, so this is cheap.
    """
    digests: set[str] = set()
    for col in (Finding.image_digest, AssetObservedTag.last_digest):
        rows = await db.execute(select(col).where(col.is_not(None)).distinct())
        for (raw,) in rows:
            norm = normalize_image_digest(raw)
            if norm:
                digests.add(norm)
    return sorted(digests)
