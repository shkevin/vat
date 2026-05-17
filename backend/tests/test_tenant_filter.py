"""Unit tests for tenant_filter SQL behavior."""

from sqlalchemy import select

from app.core.auth import tenant_filter
from app.models.finding import Finding
from app.schemas.auth import UserContext


def _ctx(*, tenant_id: str | None, cross_tenant: bool) -> UserContext:
    return UserContext(
        user_id="u1",
        email="u1@vat.local",
        tenant_id=tenant_id,
        role="admin",
        raw_identity="u1@vat.local",
        cross_tenant=cross_tenant,
    )


def test_tenant_filter_cross_tenant_compiles_to_true_predicate() -> None:
    q = select(Finding.id).where(tenant_filter(Finding, _ctx(tenant_id=None, cross_tenant=True)))
    sql = str(q)
    # Regression guard: avoid emitting invalid SQL like "tenant_id IS tenant_id".
    assert " IS " not in sql or " IS NULL" in sql


def test_tenant_filter_no_tenant_non_cross_tenant_fails_closed() -> None:
    q = select(Finding.id).where(tenant_filter(Finding, _ctx(tenant_id=None, cross_tenant=False)))
    sql = str(q)
    assert "false" in sql.lower()

