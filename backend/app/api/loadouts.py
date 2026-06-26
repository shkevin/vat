"""Asset loadouts API — server-persisted named asset sets.

Replaces the localStorage-only loadouts so they survive across browsers
and can be shared within a tenant. Visibility:

- A loadout's owner can always see, edit, and delete it.
- Other users in the same tenant can see + apply the loadout when
  ``shared_with_team`` is true; they cannot edit or delete it.
- Tenant scoping is honored — users in different tenants never see each
  other's loadouts even when shared_with_team is true.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin
from app.core.database import get_db
from app.core.tenancy import coalesced_tenant_equals, normalize_tenant_id, tenants_compatible
from app.models.asset import Asset
from app.models.asset_loadout import AssetLoadout
from app.models.finding import Finding
from app.schemas.auth import UserContext

router = APIRouter()


class LoadoutEntry(BaseModel):
    assetId: str = Field(..., max_length=512)
    branch: Optional[str] = Field(default=None, max_length=128)
    tag: Optional[str] = Field(default=None, max_length=128)


class LoadoutCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    asset_ids: list[str] = Field(default_factory=list)
    entries: Optional[list[LoadoutEntry]] = None
    shared_with_team: bool = False


class LoadoutUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    asset_ids: Optional[list[str]] = None
    entries: Optional[list[LoadoutEntry]] = None
    shared_with_team: Optional[bool] = None


class LoadoutItemsAdd(BaseModel):
    asset_ids: list[str] = Field(..., min_length=1)


def _serialize(row: AssetLoadout, viewer_email: str) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "owner_email": row.owner_email,
        "tenant_id": row.tenant_id,
        "asset_ids": list(row.asset_ids or []),
        "entries": list(row.entries or []),
        "shared_with_team": bool(row.shared_with_team),
        "is_owner": row.owner_email == viewer_email,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _visible_filter(ctx: UserContext):
    """Owner OR (same tenant AND shared_with_team)."""
    if ctx.tenant_id is None:
        return AssetLoadout.owner_email == ctx.email
    return or_(
        AssetLoadout.owner_email == ctx.email,
        (
            coalesced_tenant_equals(AssetLoadout.tenant_id, ctx.tenant_id)
            & (AssetLoadout.shared_with_team.is_(True))
        ),
    )


@router.get("")
async def list_loadouts(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    rows = (
        await db.execute(
            select(AssetLoadout)
            .where(_visible_filter(ctx))
            .order_by(AssetLoadout.updated_at.desc())
        )
    ).scalars().all()
    return {"count": len(rows), "loadouts": [_serialize(r, ctx.email) for r in rows]}


@router.post("")
async def create_loadout(
    body: LoadoutCreate,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    asset_ids = list(dict.fromkeys(body.asset_ids))  # dedupe, preserve order
    entries = [e.model_dump() for e in body.entries] if body.entries else None
    row = AssetLoadout(
        name=body.name.strip(),
        owner_email=ctx.email,
        tenant_id=normalize_tenant_id(ctx.tenant_id),
        asset_ids=asset_ids,
        entries=entries,
        shared_with_team=bool(body.shared_with_team),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _serialize(row, ctx.email)


async def _load_or_404(
    db: AsyncSession, loadout_id: str, ctx: UserContext, *, require_owner: bool = False
) -> AssetLoadout:
    row = await db.get(AssetLoadout, loadout_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Loadout not found")
    # Visibility: owner, or shared-in-tenant
    if row.owner_email != ctx.email:
        if require_owner:
            raise HTTPException(
                status_code=403, detail="Only the loadout owner can perform this action"
            )
        if not row.shared_with_team or not tenants_compatible(row.tenant_id, ctx.tenant_id):
            raise HTTPException(status_code=404, detail="Loadout not found")
    return row


@router.get("/{loadout_id}")
async def get_loadout(
    loadout_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    row = await _load_or_404(db, loadout_id, ctx)
    return _serialize(row, ctx.email)


@router.put("/{loadout_id}")
async def update_loadout(
    loadout_id: str,
    body: LoadoutUpdate,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    row = await _load_or_404(db, loadout_id, ctx, require_owner=True)
    if body.name is not None:
        row.name = body.name.strip()
    if body.asset_ids is not None:
        row.asset_ids = list(dict.fromkeys(body.asset_ids))
    if body.entries is not None:
        row.entries = [e.model_dump() for e in body.entries]
    if body.shared_with_team is not None:
        row.shared_with_team = bool(body.shared_with_team)
    await db.commit()
    await db.refresh(row)
    return _serialize(row, ctx.email)


@router.delete("/{loadout_id}")
async def delete_loadout(
    loadout_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    row = await _load_or_404(db, loadout_id, ctx, require_owner=True)
    await db.delete(row)
    await db.commit()
    return {"deleted": loadout_id}


@router.post("/{loadout_id}/items")
async def add_items(
    loadout_id: str,
    body: LoadoutItemsAdd,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
):
    """Bulk-add asset ids to an existing loadout (de-duped, idempotent)."""
    row = await _load_or_404(db, loadout_id, ctx, require_owner=True)
    incoming = [a.strip() for a in body.asset_ids if a and a.strip()]
    merged = list(dict.fromkeys([*list(row.asset_ids or []), *incoming]))
    row.asset_ids = merged
    # Mirror new ids into entries when entries is in use.
    if row.entries is not None:
        existing_in_entries = {e.get("assetId") for e in (row.entries or [])}
        for aid in incoming:
            if aid not in existing_in_entries:
                row.entries = [*list(row.entries or []), {"assetId": aid}]
    await db.commit()
    await db.refresh(row)
    return _serialize(row, ctx.email)
