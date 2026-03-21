"""Assets API — asset discovery, grouping overrides, and admin operations."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin
from app.core.database import get_db
from app.models.asset import Asset
from app.models.asset_alias import AssetAlias
from app.models.asset_merge_event import AssetMergeEvent
from app.models.finding import Finding
from app.schemas.auth import UserContext
from app.services.asset_aliases import (
    record_merge_event,
    repoint_aliases,
    resolve_canonical_asset_id,
    upsert_asset_alias,
)
from app.services.asset_resolver import infer_asset_kind
from app.services.assets_service import get_assets_with_findings

router = APIRouter()


class AssetGroupRequest(BaseModel):
    target_asset_id: str = Field(..., min_length=1, max_length=512)
    reassign_existing_findings: bool = True


class AssetUnmergeRequest(BaseModel):
    source_asset_id: str = Field(..., min_length=1, max_length=512)


@router.get("")
async def list_assets(
    include_findings: bool = Query(
        default=False, description="Include nested findings payload"
    ),
    limit: int = Query(default=0, ge=0, le=10000),
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """
    Discover canonical asset ids for CI/source targeting.
    Returns persisted assets plus findings-derived assets.
    """
    assets = await get_assets_with_findings(db, tenant_id=ctx.tenant_id, limit=limit)
    out = []
    for a in assets:
        aid = (a.get("id") or "").strip()
        kind = infer_asset_kind(aid, "")
        item = {
            "id": aid,
            "name": a.get("name") or aid,
            "type": a.get("type"),
            "source": a.get("source"),
            "branch": a.get("branch"),
            "tag": a.get("tag"),
            "kind": kind,
            "openCount": a.get("openCount"),
            "inReviewCount": a.get("inReviewCount"),
        }
        if include_findings:
            item["findings"] = a.get("findings") or []
        out.append(item)
    return {"count": len(out), "assets": out}


@router.delete("/{asset_id:path}")
async def delete_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """
    Delete an asset and all findings that belong to this asset key.

    Asset key matching follows the frontend grouping logic:
    - finding.image == asset_id OR finding.component == asset_id
    """
    findings_q = delete(Finding).where(
        (Finding.image == asset_id) | (Finding.component == asset_id)
    )
    if ctx.tenant_id is not None:
        findings_q = findings_q.where(
            (Finding.tenant_id == ctx.tenant_id) | (Finding.tenant_id.is_(None))
        )
    findings_result = await db.execute(findings_q)
    findings_deleted = findings_result.rowcount or 0

    asset_result = await db.execute(delete(Asset).where(Asset.id == asset_id))
    asset_deleted = (asset_result.rowcount or 0) > 0

    if findings_deleted == 0 and not asset_deleted:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Asset not found")

    await db.commit()
    return {"deleted_findings": findings_deleted, "deleted_asset": asset_deleted}


@router.post("/{asset_id:path}/group")
async def group_asset_into_target(
    asset_id: str,
    body: AssetGroupRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """
    Group/merge one asset key into another canonical asset key.

    Effects:
    - stores a persistent alias so future ingests auto-map source -> canonical
    - rewrites existing findings that still reference source asset key
    - removes the source asset row
    """
    source_asset_id = (asset_id or "").strip()
    requested_target = (body.target_asset_id or "").strip()
    if not source_asset_id or not requested_target:
        raise HTTPException(status_code=422, detail="source and target asset ids are required")

    canonical_target = await resolve_canonical_asset_id(db, requested_target)
    if not canonical_target:
        canonical_target = requested_target
    if source_asset_id == canonical_target:
        raise HTTPException(
            status_code=400, detail="source asset id must differ from target asset id"
        )

    await upsert_asset_alias(
        db,
        source_asset_id=source_asset_id,
        canonical_asset_id=canonical_target,
        created_by=getattr(ctx, "email", None),
    )
    repointed_aliases = await repoint_aliases(
        db, old_canonical_id=source_asset_id, new_canonical_id=canonical_target
    )

    source_asset = await db.get(Asset, source_asset_id)
    target_asset = await db.get(Asset, canonical_target)
    created_target_asset = False
    if not target_asset:
        target_asset = Asset(
            id=canonical_target,
            name=canonical_target,
            type=(source_asset.type if source_asset else "package"),
            source=(source_asset.source if source_asset else "manual-grouping"),
            branch=(source_asset.branch if source_asset else None),
            tag=(source_asset.tag if source_asset else None),
        )
        db.add(target_asset)
        created_target_asset = True

    findings_updated = 0
    if body.reassign_existing_findings:
        q = select(Finding).where(
            or_(
                Finding.image == source_asset_id,
                Finding.component == source_asset_id,
                Finding.tag == source_asset_id,
            )
        )
        if ctx.tenant_id is not None:
            q = q.where(or_(Finding.tenant_id == ctx.tenant_id, Finding.tenant_id.is_(None)))
        result = await db.execute(q)
        rows = list(result.scalars().all())
        for finding in rows:
            changed = False
            prev_values: dict[str, str] = {}
            next_values: dict[str, str] = {}
            if (finding.image or "").strip() == source_asset_id:
                prev_values["image"] = source_asset_id
                finding.image = canonical_target
                next_values["image"] = canonical_target
                changed = True
            if (finding.component or "").strip() == source_asset_id:
                prev_values["component"] = source_asset_id
                finding.component = canonical_target
                next_values["component"] = canonical_target
                changed = True
            if (finding.tag or "").strip() == source_asset_id:
                prev_values["tag"] = source_asset_id
                finding.tag = canonical_target
                next_values["tag"] = canonical_target
                changed = True
            if changed:
                findings_updated += 1
                await record_merge_event(
                    db,
                    source_asset_id=source_asset_id,
                    target_asset_id=canonical_target,
                    finding_id=finding.id,
                    prev_values=prev_values,
                    next_values=next_values,
                    created_by=getattr(ctx, "email", None),
                )

    source_deleted = False
    if source_asset:
        await db.delete(source_asset)
        source_deleted = True

    await db.commit()
    return {
        "source_asset_id": source_asset_id,
        "target_asset_id": canonical_target,
        "findings_updated": findings_updated,
        "alias_saved": True,
        "repointed_aliases": repointed_aliases,
        "created_target_asset": created_target_asset,
        "deleted_source_asset": source_deleted,
    }


@router.get("/{asset_id:path}/aliases")
async def list_asset_aliases(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    canonical_id = (asset_id or "").strip()
    result = await db.execute(
        select(AssetAlias)
        .where(AssetAlias.canonical_asset_id == canonical_id)
        .order_by(AssetAlias.source_asset_id.asc())
    )
    rows = list(result.scalars().all())
    return {
        "canonical_asset_id": canonical_id,
        "aliases": [
            {
                "source_asset_id": r.source_asset_id,
                "canonical_asset_id": r.canonical_asset_id,
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.post("/{asset_id:path}/unmerge")
async def unmerge_asset_alias(
    asset_id: str,
    body: AssetUnmergeRequest,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    canonical_id = (asset_id or "").strip()
    source_id = (body.source_asset_id or "").strip()
    if not canonical_id or not source_id:
        raise HTTPException(status_code=422, detail="canonical and source asset ids are required")
    if source_id == canonical_id:
        raise HTTPException(status_code=400, detail="source and canonical ids must differ")

    alias = await db.get(AssetAlias, source_id)
    if not alias or alias.canonical_asset_id != canonical_id:
        raise HTTPException(status_code=404, detail="Alias not found for canonical asset")

    result = await db.execute(
        select(AssetMergeEvent)
        .where(
            AssetMergeEvent.source_asset_id == source_id,
            AssetMergeEvent.target_asset_id == canonical_id,
            AssetMergeEvent.reverted_at.is_(None),
        )
        .order_by(AssetMergeEvent.id.asc())
    )
    events = list(result.scalars().all())

    restored_findings = 0
    for ev in events:
        finding = await db.get(Finding, ev.finding_id)
        if not finding:
            ev.reverted_at = ev.reverted_at or alias.updated_at
            continue
        if ctx.tenant_id is not None and finding.tenant_id not in (None, ctx.tenant_id):
            continue

        changed = False
        prev_values = ev.prev_values or {}
        next_values = ev.next_values or {}
        for field in ("image", "component", "tag"):
            prev = prev_values.get(field)
            nxt = next_values.get(field)
            if not prev or not nxt:
                continue
            current = (getattr(finding, field, None) or "").strip()
            if current == nxt:
                setattr(finding, field, prev)
                changed = True
        if changed:
            restored_findings += 1
        ev.reverted_at = ev.reverted_at or alias.updated_at

    # Remove alias so future ingests stop canonicalizing this source id.
    await db.delete(alias)

    # Recreate source asset row if needed (merge deletes it).
    source_asset = await db.get(Asset, source_id)
    if not source_asset:
        target_asset = await db.get(Asset, canonical_id)
        db.add(
            Asset(
                id=source_id,
                name=source_id,
                type=(target_asset.type if target_asset else "package"),
                source=(target_asset.source if target_asset else "manual-unmerge"),
                branch=None,
                tag=None,
            )
        )

    await db.commit()
    return {
        "canonical_asset_id": canonical_id,
        "source_asset_id": source_id,
        "alias_removed": True,
        "restored_findings": restored_findings,
    }
