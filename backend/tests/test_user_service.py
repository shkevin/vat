"""Tests for user service."""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.user_service import (
    get_user_by_email,
    get_user_by_email_in_google_tenant,
    get_google_tenant,
)


@pytest.mark.asyncio
async def test_get_user_by_email_returns_user(db: AsyncSession):
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-1', 'Tenant 1', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, created_at) "
            "VALUES ('u-1', 't-1', 'alice@co.com', 'reviewer', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"
        )
    )
    await db.commit()

    user = await get_user_by_email(db, "alice@co.com")
    assert user is not None
    assert user.id == "u-1"
    assert user.tenant_id == "t-1"
    assert user.email == "alice@co.com"
    assert user.role == "reviewer"


@pytest.mark.asyncio
async def test_get_user_by_email_returns_none_when_not_found(db: AsyncSession):
    user = await get_user_by_email(db, "nobody@co.com")
    assert user is None


@pytest.mark.asyncio
async def test_get_user_by_email_case_insensitive(db: AsyncSession):
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-2', 'Tenant 2', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, created_at) "
            "VALUES ('u-2', 't-2', 'Bob@Co.COM', 'admin', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"
        )
    )
    await db.commit()

    user = await get_user_by_email(db, "bob@co.com")
    assert user is not None
    assert user.id == "u-2"
    assert user.role == "admin"


@pytest.mark.asyncio
async def test_get_google_tenant_returns_tenant_with_google_auth(db: AsyncSession):
    """get_google_tenant returns first tenant with auth_method=google."""
    # Isolate from other tests: remove users first (FK), then google tenants
    await db.execute(text("DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE auth_method = 'google')"))
    await db.execute(text("DELETE FROM tenants WHERE auth_method = 'google'"))
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-local', 'Local', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-google', 'Google Org', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = EXCLUDED.auth_method"
        )
    )
    await db.commit()

    tenant = await get_google_tenant(db)
    assert tenant is not None
    assert tenant.id == "t-google"
    assert tenant.auth_method == "google"


@pytest.mark.asyncio
async def test_get_google_tenant_returns_none_when_no_google_tenant(db: AsyncSession):
    """get_google_tenant returns None when no tenant has auth_method=google."""
    # Isolate from other tests: remove users first (FK), then google tenants
    await db.execute(text("DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE auth_method = 'google')"))
    await db.execute(text("DELETE FROM tenants WHERE auth_method = 'google'"))
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-only-local', 'Local Only', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.commit()

    tenant = await get_google_tenant(db)
    assert tenant is None


@pytest.mark.asyncio
async def test_get_user_by_email_in_google_tenant_returns_user(db: AsyncSession):
    """get_user_by_email_in_google_tenant returns user when in Google-enabled tenant."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-g', 'Google', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = EXCLUDED.auth_method"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, created_at) "
            "VALUES ('u-g', 't-g', 'google@org.com', 'admin', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"
        )
    )
    await db.commit()

    user = await get_user_by_email_in_google_tenant(db, "google@org.com")
    assert user is not None
    assert user.id == "u-g"
    assert user.tenant_id == "t-g"


@pytest.mark.asyncio
async def test_get_user_by_email_in_google_tenant_returns_none_for_local_tenant(db: AsyncSession):
    """get_user_by_email_in_google_tenant returns None when user is in local-only tenant."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-l', 'Local', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, created_at) "
            "VALUES ('u-l', 't-l', 'local@org.com', 'reviewer', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email"
        )
    )
    await db.commit()

    user = await get_user_by_email_in_google_tenant(db, "local@org.com")
    assert user is None
