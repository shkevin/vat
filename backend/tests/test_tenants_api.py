"""Tests for tenants API — CRUD, delete guard for default tenant."""

import bcrypt
import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_delete_default_tenant_blocked_when_single_admin(client, db):
    """DELETE /api/tenants/t-default returns 400 when there is only one admin."""
    # Clean slate: remove existing users/tenants so admin count is exactly 1
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default Org', NOW(), 'local')"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    login_res = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    res = await client.delete(
        "/api/tenants/t-default",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "default tenant" in res.json().get("detail", "").lower()
    assert (
        "single admin" in res.json().get("detail", "").lower()
        or "one admin" in res.json().get("detail", "").lower()
    )


@pytest.mark.asyncio
async def test_delete_default_tenant_allowed_when_multiple_admins(client, db):
    """DELETE /api/tenants/t-default succeeds when there are 2+ admins."""
    # Clean slate so we have exactly 2 admins
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default Org', NOW(), 'local')"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw, NOW()), "
            "       ('admin2', 't-default', 'admin2@vat.local', 'admin', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    login_res = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    res = await client.delete(
        "/api/tenants/t-default",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 204
