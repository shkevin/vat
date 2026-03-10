"""Tests for OAuth client credentials and ingest with OAuth token."""

import bcrypt
import pytest
from sqlalchemy import text

from app.core.oauth import create_ingest_token, decode_ingest_token
from app.services.oauth_clients import (
    create_oauth_client,
    list_oauth_clients,
    revoke_oauth_client,
    rotate_oauth_client,
    validate_oauth_client,
)


# --- Service-level tests ---


@pytest.mark.asyncio
async def test_create_and_validate_oauth_client(db):
    """Create OAuth client, validate credentials, then fail with wrong secret."""
    client_id, client_secret, msg = await create_oauth_client(db, "trivy-ci")
    assert client_id.startswith("vat_oauth_")
    assert len(client_secret) > 20
    assert "Store" in msg

    result = await validate_oauth_client(db, client_id, client_secret)
    assert result is not None
    source_id, user = result
    assert source_id == "trivy-ci"
    assert "trivy-ci" in user

    wrong = await validate_oauth_client(db, client_id, "wrong-secret")
    assert wrong is None


@pytest.mark.asyncio
async def test_list_oauth_clients(db):
    """Create clients, list them (no secrets)."""
    await create_oauth_client(db, "trivy-ci")
    await create_oauth_client(db, "snyk-prod")

    clients = await list_oauth_clients(db)
    assert len(clients) == 2
    source_ids = {c.source_id for c in clients}
    assert "trivy-ci" in source_ids
    assert "snyk-prod" in source_ids


@pytest.mark.asyncio
async def test_rotate_invalidates_old_secret(db):
    """Rotate invalidates previous client_secret."""
    client_id, old_secret, _ = await create_oauth_client(db, "trivy-ci")
    _, new_secret, _ = await rotate_oauth_client(db, "trivy-ci")

    assert await validate_oauth_client(db, client_id, old_secret) is None
    assert await validate_oauth_client(db, client_id, new_secret) is not None


@pytest.mark.asyncio
async def test_revoke_oauth_client(db):
    """Revoke removes OAuth client."""
    client_id, client_secret, _ = await create_oauth_client(db, "trivy-ci")
    assert await validate_oauth_client(db, client_id, client_secret) is not None

    existed = await revoke_oauth_client(db, "trivy-ci")
    assert existed
    assert await validate_oauth_client(db, client_id, client_secret) is None

    existed_again = await revoke_oauth_client(db, "trivy-ci")
    assert not existed_again


@pytest.mark.asyncio
async def test_create_oauth_client_requires_source_id(db):
    """Create OAuth client with empty sourceId raises."""
    with pytest.raises(ValueError, match="sourceId"):
        await create_oauth_client(db, "")
    with pytest.raises(ValueError, match="sourceId"):
        await create_oauth_client(db, "   ")


@pytest.mark.asyncio
async def test_rotate_oauth_client_nonexistent_raises(db):
    """Rotate for nonexistent source raises."""
    with pytest.raises(ValueError, match="No OAuth client"):
        await rotate_oauth_client(db, "nonexistent")


# --- Token creation/decoding ---


def test_create_and_decode_ingest_token():
    """create_ingest_token produces valid JWT; decode extracts source_id."""
    token = create_ingest_token("trivy-ci")
    assert isinstance(token, str)
    assert len(token) > 20

    source_id = decode_ingest_token(token)
    assert source_id == "trivy-ci"


def test_decode_invalid_token_returns_none():
    """Invalid token returns None."""
    assert decode_ingest_token("not-a-jwt") is None
    assert decode_ingest_token("") is None


# --- API tests ---


async def _admin_token(client, db):
    """Create admin user and return JWT."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default', NOW(), 'local') ON CONFLICT (id) DO NOTHING"
        )
    )
    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    login_res = await client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login_res.status_code == 200
    return login_res.json()["token"]


@pytest.mark.asyncio
async def test_oauth_token_endpoint(client, db):
    """POST /api/oauth/token returns access_token for valid client credentials."""
    client_id, client_secret, _ = await create_oauth_client(db, "trivy-ci")
    await db.commit()

    res = await client.post(
        "/api/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 3600

    source_id = decode_ingest_token(data["access_token"])
    assert source_id == "trivy-ci"


@pytest.mark.asyncio
async def test_oauth_token_endpoint_invalid_credentials(client, db):
    """POST /api/oauth/token returns 401 for invalid credentials."""
    res = await client.post(
        "/api/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "vat_oauth_nonexistent",
            "client_secret": "wrong",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_oauth_token_endpoint_wrong_grant_type(client, db):
    """POST /api/oauth/token returns 400 for wrong grant_type."""
    client_id, client_secret, _ = await create_oauth_client(db, "trivy-ci")
    await db.commit()

    res = await client.post(
        "/api/oauth/token",
        data={
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_settings_oauth_clients_crud(client, db):
    """Create, list, rotate, revoke OAuth client via settings API."""
    token = await _admin_token(client, db)

    # Create
    create_res = await client.post(
        "/api/settings/oauth-clients",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"sourceId": "trivy-ci"},
    )
    assert create_res.status_code == 200
    data = create_res.json()
    assert data["sourceId"] == "trivy-ci"
    assert "clientId" in data
    assert "clientSecret" in data

    # List (via ingest-keys which now includes oauthClients)
    keys_res = await client.get(
        "/api/settings/ingest-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert keys_res.status_code == 200
    keys_data = keys_res.json()
    assert "oauthClients" in keys_data
    oauth = next((c for c in keys_data["oauthClients"] if c["sourceId"] == "trivy-ci"), None)
    assert oauth is not None
    assert oauth["clientId"] == data["clientId"]

    # Rotate
    rotate_res = await client.post(
        "/api/settings/oauth-clients/trivy-ci/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert rotate_res.status_code == 200
    rot_data = rotate_res.json()
    assert rot_data["clientId"] == data["clientId"]
    assert rot_data["clientSecret"] != data["clientSecret"]

    # Revoke
    revoke_res = await client.delete(
        "/api/settings/oauth-clients/trivy-ci",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["revoked"] is True


@pytest.mark.asyncio
async def test_ingest_with_oauth_token(client, db):
    """POST /api/ingest accepts OAuth Bearer token."""
    client_id, client_secret, _ = await create_oauth_client(db, "trivy-ci")
    await db.commit()

    # Get token
    token_res = await client.post(
        "/api/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert token_res.status_code == 200
    access_token = token_res.json()["access_token"]

    # Seed source config so parser resolves to canonical
    from datetime import datetime, timezone
    from sqlalchemy import select
    from app.models.settings_model import SettingsKV

    r = await db.execute(select(SettingsKV).where(SettingsKV.key == "sources"))
    row = r.scalar_one_or_none()
    sources = [{"id": "trivy-ci", "name": "trivy-ci", "adapter": "manual", "parser": "canonical"}]
    if row:
        row.value = sources
    else:
        db.add(SettingsKV(key="sources", value=sources, updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    await db.commit()

    # Ingest with OAuth token (component + branch required for asset context)
    payload = {"source": "trivy-ci", "findings": [{"cve_id": "CVE-2024-9999", "severity": "High", "description": "Test", "component": "test-pkg 1.0", "branch": "main"}]}
    ingest_res = await client.post(
        "/api/ingest",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
    )
    assert ingest_res.status_code == 200
    out = ingest_res.json()
    assert out["source"] == "trivy-ci"
    assert out["created"] >= 1 or out["merged"] >= 1
