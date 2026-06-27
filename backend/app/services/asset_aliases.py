"""Asset alias override helpers."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_alias import AssetAlias
from app.models.asset_merge_event import AssetMergeEvent


def _clean_asset_id(asset_id: str) -> str:
    return str(asset_id or "").strip()


async def resolve_canonical_asset_id(
    db: AsyncSession, asset_id: str, *, max_depth: int = 16
) -> str:
    """
    Resolve source asset id to canonical id by following alias links.
    Stops on missing link, self-link, loop, or max_depth.
    """
    current = _clean_asset_id(asset_id)
    if not current:
        return current

    seen: set[str] = set()
    depth = 0
    while current and current not in seen and depth < max_depth:
        seen.add(current)
        row = await db.get(AssetAlias, current)
        if not row:
            break
        nxt = _clean_asset_id(row.canonical_asset_id)
        if not nxt or nxt == current:
            break
        current = nxt
        depth += 1
    return current


async def upsert_asset_alias(
    db: AsyncSession,
    *,
    source_asset_id: str,
    canonical_asset_id: str,
    created_by: str | None = None,
) -> AssetAlias:
    source = _clean_asset_id(source_asset_id)
    canonical = _clean_asset_id(canonical_asset_id)
    if not source or not canonical:
        raise ValueError("source_asset_id and canonical_asset_id are required")
    if source == canonical:
        raise ValueError("source_asset_id cannot equal canonical_asset_id")

    # Bridge durable decisions across the merge: alias old-asset DSKs to the new
    # canonical so a prior Risk Accepted survives. Deferred import avoids a cycle.
    from app.services.decision_ledger import register_decision_aliases_for_asset_merge

    row = await db.get(AssetAlias, source)
    if row:
        changed = row.canonical_asset_id != canonical
        row.canonical_asset_id = canonical
        if created_by:
            row.created_by = created_by
        if changed:
            await register_decision_aliases_for_asset_merge(
                db, old_asset_id=source, new_asset_id=canonical
            )
        return row

    row = AssetAlias(
        source_asset_id=source,
        canonical_asset_id=canonical,
        created_by=created_by,
    )
    db.add(row)
    await register_decision_aliases_for_asset_merge(
        db, old_asset_id=source, new_asset_id=canonical
    )
    return row


async def repoint_aliases(
    db: AsyncSession, *, old_canonical_id: str, new_canonical_id: str
) -> int:
    """Repoint aliases that currently target old canonical id."""
    old_id = _clean_asset_id(old_canonical_id)
    new_id = _clean_asset_id(new_canonical_id)
    if not old_id or not new_id or old_id == new_id:
        return 0

    result = await db.execute(
        select(AssetAlias).where(AssetAlias.canonical_asset_id == old_id)
    )
    rows = list(result.scalars().all())
    changed = 0
    for row in rows:
        if row.source_asset_id == new_id:
            continue
        row.canonical_asset_id = new_id
        changed += 1
    return changed


async def record_merge_event(
    db: AsyncSession,
    *,
    source_asset_id: str,
    target_asset_id: str,
    finding_id: str,
    prev_values: dict,
    next_values: dict,
    created_by: str | None = None,
) -> AssetMergeEvent:
    row = AssetMergeEvent(
        source_asset_id=_clean_asset_id(source_asset_id),
        target_asset_id=_clean_asset_id(target_asset_id),
        finding_id=str(finding_id),
        prev_values=prev_values or {},
        next_values=next_values or {},
        created_by=created_by,
    )
    db.add(row)
    return row
