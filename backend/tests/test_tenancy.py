"""Unit tests for tenant normalization helpers."""

from app.core.tenancy import (
    DEFAULT_TENANT_ID,
    coalesced_tenant_equals,
    normalize_tenant_id,
    row_tenant_visible,
    tenants_compatible,
)
from app.schemas.auth import UserContext


def _ctx(*, tenant_id: str | None, cross_tenant: bool = False) -> UserContext:
    return UserContext(
        user_id="u-1",
        email="u1@vat.local",
        tenant_id=tenant_id,
        role="reviewer",
        raw_identity="u1@vat.local",
        cross_tenant=cross_tenant,
    )


def test_normalize_tenant_id_defaults_missing_values() -> None:
    assert normalize_tenant_id(None) == DEFAULT_TENANT_ID
    assert normalize_tenant_id("") == DEFAULT_TENANT_ID
    assert normalize_tenant_id("  ") == DEFAULT_TENANT_ID
    assert normalize_tenant_id("t-custom") == "t-custom"


def test_tenants_compatible_treats_null_as_default() -> None:
    assert tenants_compatible(None, DEFAULT_TENANT_ID) is True
    assert tenants_compatible(DEFAULT_TENANT_ID, None) is True
    assert tenants_compatible("t-other", DEFAULT_TENANT_ID) is False


def test_row_tenant_visible_uses_normalized_comparison() -> None:
    ctx = _ctx(tenant_id=DEFAULT_TENANT_ID)
    assert row_tenant_visible(None, ctx) is True
    assert row_tenant_visible(DEFAULT_TENANT_ID, ctx) is True
    assert row_tenant_visible("t-other", ctx) is False


def test_row_tenant_visible_cross_tenant_and_fail_closed() -> None:
    assert row_tenant_visible("t-other", _ctx(tenant_id=None, cross_tenant=True)) is True
    assert row_tenant_visible(DEFAULT_TENANT_ID, _ctx(tenant_id=None)) is False


def test_coalesced_tenant_equals_builds_sql() -> None:
    from app.models.finding import Finding

    expr = coalesced_tenant_equals(Finding.tenant_id, None)
    assert "coalesce" in str(expr).lower()
