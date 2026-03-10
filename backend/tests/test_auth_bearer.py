"""Tests for JWT Bearer auth — API requests with Authorization header."""

import bcrypt
import pytest
from sqlalchemy import text

from app.core.jwt import create_token


@pytest.mark.asyncio
async def test_findings_api_accepts_bearer_token(client, db):
    """API accepts valid JWT in Authorization: Bearer header."""
    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
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

    # Login to get token
    login_res = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    # Call protected endpoint with Bearer token
    res = await client.get(
        "/api/tenants",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_api_accepts_valid_jwt_directly(client, db):
    """API accepts a JWT created directly (e.g. from OAuth callback)."""
    token = create_token(
        user_id="admin",
        email="admin@vat.local",
        tenant_id="t-default",
        role="admin",
    )

    # Ensure admin user exists for tenant lookup
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', 'x', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id"
        )
    )
    await db.commit()

    res = await client.get(
        "/api/tenants",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
