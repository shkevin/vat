"""Tenants API — CRUD for multi-tenant management."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_admin
from app.core.database import get_db
from app.core.tenancy import DEFAULT_TENANT_ID
from app.models.user import Tenant
from app.schemas.auth import UserContext
from app.schemas.tenant import TenantCreate, TenantRead, TenantUpdate

router = APIRouter()


@router.get("", response_model=list[TenantRead])
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """List all tenants. Admin only."""
    result = await db.execute(select(Tenant).order_by(Tenant.name))
    tenants = result.scalars().all()
    return [TenantRead.model_validate(t) for t in tenants]


@router.post("", response_model=TenantRead, status_code=201)
async def create_tenant(
    body: TenantCreate,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Create a tenant. Admin only."""
    tenant = Tenant(id=body.id, name=body.name, auth_method=body.auth_method)
    db.add(tenant)
    try:
        await db.commit()
        await db.refresh(tenant)
    except Exception:
        await db.rollback()
        logging.getLogger(__name__).exception(
            "tenants.create_tenant failed for id=%s", body.id
        )
        raise HTTPException(status_code=409, detail="conflict creating tenant")
    return TenantRead.model_validate(tenant)


@router.patch("/{tenant_id}", response_model=TenantRead)
async def update_tenant(
    tenant_id: str,
    body: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update a tenant. Admin only."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if body.auth_method is not None:
        tenant.auth_method = body.auth_method
    await db.commit()
    await db.refresh(tenant)
    return TenantRead.model_validate(tenant)


@router.delete("/{tenant_id}", status_code=204)
async def delete_tenant(
    tenant_id: str,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Delete a tenant. Admin only.

    Refuses to delete when the tenant still owns findings, audit events,
    or asset loadouts — those rows would otherwise be orphaned with a
    pointer to a vanished tenant id, invisible to other tenants but
    silently revivable if the id is ever reused. Pass ``?force=true`` to
    delete anyway (legacy/test escape hatch); orphans are still left in
    place — explicit cleanup is the caller's responsibility.

    Users in this tenant always have their tenant_id set to None.
    """
    from sqlalchemy import update

    from app.models.audit_event import AuditEvent
    from app.models.asset_loadout import AssetLoadout
    from app.models.finding import Finding
    from app.models.user import User

    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if tenant_id == DEFAULT_TENANT_ID:
        admin_count = await db.scalar(
            select(func.count()).select_from(User).where(User.role == "admin")
        )
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the default tenant while there is only one admin.",
            )
    if not force:
        # Block deletion when dependent rows exist; surface counts so the
        # operator knows what migration is needed before retrying with force=true.
        finding_count = await db.scalar(
            select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant_id)
        )
        audit_count = await db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
        )
        loadout_count = await db.scalar(
            select(func.count())
            .select_from(AssetLoadout)
            .where(AssetLoadout.tenant_id == tenant_id)
        )
        if (finding_count or 0) + (audit_count or 0) + (loadout_count or 0) > 0:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Tenant has dependent rows: findings={finding_count}, "
                    f"audit_events={audit_count}, loadouts={loadout_count}. "
                    "Migrate or delete them first, or pass ?force=true to override."
                ),
            )
    # Unassign users from this tenant before deleting
    await db.execute(
        update(User).where(User.tenant_id == tenant_id).values(tenant_id=None)
    )
    await db.delete(tenant)
    await db.commit()
