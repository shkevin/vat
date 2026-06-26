"""Mixin to stamp tenant-owned rows with the default tenant on write."""

from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.orm import validates

from app.core.tenancy import DEFAULT_TENANT_ID, normalize_tenant_id


class TenantScopedMixin:
    tenant_id: str | None

    @validates("tenant_id")
    def _normalize_tenant_id(self, _key: str, value: str | None) -> str:
        return normalize_tenant_id(value)


@event.listens_for(TenantScopedMixin, "before_insert", propagate=True)
def _stamp_tenant_before_insert(_mapper, _connection, target: TenantScopedMixin) -> None:
    target.tenant_id = normalize_tenant_id(getattr(target, "tenant_id", None))


@event.listens_for(TenantScopedMixin, "before_update", propagate=True)
def _stamp_tenant_before_update(_mapper, _connection, target: TenantScopedMixin) -> None:
    if getattr(target, "tenant_id", None) in (None, ""):
        target.tenant_id = DEFAULT_TENANT_ID
