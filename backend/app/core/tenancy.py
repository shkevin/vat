"""Tenant defaults for the current single-tenant VAT deployment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func

if TYPE_CHECKING:
    from app.schemas.auth import UserContext

DEFAULT_TENANT_ID = "t-default"


def normalize_tenant_id(tenant_id: str | None) -> str:
    """Map missing/blank tenant ids to the bootstrap tenant."""
    cleaned = (tenant_id or "").strip()
    return cleaned or DEFAULT_TENANT_ID


def default_tenant_id(tenant_id: str | None = None) -> str:
    """Return the tenant id VAT should use while multi-tenancy is disabled."""
    return normalize_tenant_id(tenant_id)


def tenants_compatible(left: str | None, right: str | None) -> bool:
    """True when two tenant ids refer to the same scoped org (NULL == default)."""
    return normalize_tenant_id(left) == normalize_tenant_id(right)


def coalesced_tenant_equals(column: Any, tenant_id: str | None) -> Any:
    """SQL: ``coalesce(column, default) = normalize(tenant_id)``."""
    return func.coalesce(column, DEFAULT_TENANT_ID) == normalize_tenant_id(tenant_id)


def row_tenant_visible(row_tenant_id: str | None, ctx: UserContext) -> bool:
    """Post-load visibility aligned with list queries and normalized tenant ids."""
    if ctx.cross_tenant:
        return True
    if ctx.tenant_id is None:
        return False
    return tenants_compatible(row_tenant_id, ctx.tenant_id)
