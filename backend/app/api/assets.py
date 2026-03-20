"""Assets API — asset discovery and admin operations."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin
from app.core.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.schemas.auth import UserContext
from app.services.asset_resolver import infer_asset_kind
from app.services.assets_service import get_assets_with_findings

router = APIRouter()


@router.get("")
async def list_assets(
    include_findings: bool = Query(default=False, description="Include nested findings payload"),
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
