"""Unit tests for tenant_filter SQL behavior."""

from sqlalchemy import select

from app.core.auth import tenant_filter
from app.core.tenancy import row_tenant_visible
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


def test_tenant_filter_single_default_tenant_does_not_compare_tenant_ids() -> None:
    q = select(Finding.id).where(
        tenant_filter(Finding, _ctx(tenant_id="some-other-tenant", cross_tenant=False))
    )
    sql = str(q)
    assert "tenant_id" not in sql


def test_row_tenant_visible_allows_legacy_null_tenant_rows() -> None:
    ctx = _ctx(tenant_id="t-default", cross_tenant=False)
    assert row_tenant_visible(None, ctx) is True
    assert row_tenant_visible("t-default", ctx) is True


def test_row_tenant_visible_hides_conflicting_tenant_ids() -> None:
    ctx = _ctx(tenant_id="t-default", cross_tenant=False)
    assert row_tenant_visible("t-other", ctx) is False


def test_row_tenant_visible_fails_closed_without_caller_tenant() -> None:
    ctx = _ctx(tenant_id=None, cross_tenant=False)
    assert row_tenant_visible(None, ctx) is False
    assert row_tenant_visible("t-default", ctx) is False

