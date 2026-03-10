"""Tests for auth API — login, JWT, tenant auth_method enforcement."""

import bcrypt
import pytest
from sqlalchemy import text

from app.core.jwt import decode_token


@pytest.mark.asyncio
async def test_login_returns_user_and_token(client, db):
    """POST /api/auth/login returns user dict and JWT for valid credentials."""
    pw_hash = bcrypt.hashpw(b"secret123", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-auth-ok', 'Auth Tenant', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('u-auth-ok', 't-auth-ok', 'test-ok@vat.local', 'reviewer', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    res = await client.post(
        "/api/auth/login",
        json={"username": "u-auth-ok", "password": "secret123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "user" in data
    assert data["user"]["id"] == "u-auth-ok"
    assert data["user"]["email"] == "test-ok@vat.local"
    assert data["user"]["role"] == "reviewer"
    assert data["user"]["tenant_id"] == "t-auth-ok"
    assert "token" in data
    assert isinstance(data["token"], str)

    # Token is valid JWT
    payload = decode_token(data["token"])
    assert payload is not None
    assert payload["sub"] == "test-ok@vat.local"
    assert payload["user_id"] == "u-auth-ok"
    assert payload["role"] == "reviewer"


@pytest.mark.asyncio
async def test_login_rejects_invalid_password(client, db):
    """POST /api/auth/login returns 401 for wrong password."""
    pw_hash = bcrypt.hashpw(b"correct", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-auth-badpw', 'X', NOW(), 'local') "
            "ON CONFLICT (id) DO NOTHING"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('u-auth-badpw', 't-auth-badpw', 'x@v.local', 'reviewer', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    res = await client.post(
        "/api/auth/login",
        json={"username": "u-auth-badpw", "password": "wrong"},
    )
    assert res.status_code == 401
    assert "Invalid" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_rejects_google_tenant_user_with_password(client, db):
    """POST /api/auth/login returns 401 when user's tenant has auth_method=google."""
    pw_hash = bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-auth-google', 'Google Tenant', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = 'google'"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('u-auth-google', 't-auth-google', 'g@v.local', 'reviewer', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    res = await client.post(
        "/api/auth/login",
        json={"username": "u-auth-google", "password": "secret"},
    )
    assert res.status_code == 401
    assert "Google" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_rejects_empty_credentials(client):
    """POST /api/auth/login returns 401 for empty username or password."""
    res = await client.post(
        "/api/auth/login",
        json={"username": "", "password": "x"},
    )
    assert res.status_code == 401

    res = await client.post(
        "/api/auth/login",
        json={"username": "u", "password": ""},
    )
    assert res.status_code == 401
