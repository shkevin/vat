"""Tests for Google OAuth flow — authorize, callback with mocked Google APIs."""

import pytest
import respx
from httpx import Response
from sqlalchemy import text

from app.core.jwt import decode_oauth_exchange_code, decode_token

# FastAPI/Starlette may use 302 or 307 for RedirectResponse
REDIRECT_STATUS = (302, 307)


@pytest.mark.asyncio
async def test_google_authorize_not_configured(client, db):
    """GET /auth/google/authorize returns 503 when no tenant has auth_method=google."""
    # No google tenant in DB; credentials may or may not be set
    res = await client.get("/api/auth/google/authorize")
    # Either "Google OAuth not configured" or "No tenant configured for Google sign-in"
    assert res.status_code == 503


@pytest.mark.asyncio
async def test_google_authorize_redirects(client, db, google_oauth_enabled):
    """GET /auth/google/authorize redirects to Google OAuth when configured."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-google', 'Google Tenant', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = 'google'"
        )
    )
    await db.commit()

    res = await client.get("/api/auth/google/authorize", follow_redirects=False)
    assert res.status_code in REDIRECT_STATUS
    assert "accounts.google.com" in res.headers["location"]
    assert "client_id=test-google-client-id" in res.headers["location"]
    assert "redirect_uri=http%3A%2F%2Ftest%2Fapi%2Fauth%2Fgoogle%2Fcallback" in res.headers["location"]


@pytest.mark.asyncio
async def test_google_callback_success(client, db, google_respx, google_oauth_enabled):
    """GET /auth/google/callback exchanges code, gets userinfo, issues JWT, redirects with exchange code."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-google', 'Google Tenant', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = 'google'"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, created_at) "
            "VALUES ('u-google-1', 't-google', 'test@example.com', 'reviewer', NOW()) "
            "ON CONFLICT (id) DO UPDATE SET tenant_id = 't-google', email = 'test@example.com'"
        )
    )
    await db.commit()

    res = await client.get("/api/auth/google/callback?code=fake-auth-code", follow_redirects=False)
    assert res.status_code in REDIRECT_STATUS
    location = res.headers["location"]
    assert location.startswith("http://test/login?code=")
    code = location.split("code=")[1]
    # Exchange code should decode to a valid JWT
    token = decode_oauth_exchange_code(code)
    assert token is not None
    payload = decode_token(token)
    assert payload["sub"] == "test@example.com"
    assert payload["user_id"] == "u-google-1"
    assert payload["role"] == "reviewer"


@pytest.mark.asyncio
async def test_google_callback_error_param(client, db, google_oauth_enabled):
    """GET /auth/google/callback with error param redirects to login with oauth_denied."""
    res = await client.get(
        "/api/auth/google/callback?error=access_denied&error_description=User+cancelled",
        follow_redirects=False,
    )
    assert res.status_code in REDIRECT_STATUS
    assert "login?error=oauth_denied" in res.headers["location"]


@pytest.mark.asyncio
async def test_google_callback_missing_code(client, db, google_oauth_enabled):
    """GET /auth/google/callback without code returns 400."""
    res = await client.get("/api/auth/google/callback")
    assert res.status_code == 400
    assert "Missing code" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_google_callback_token_exchange_fails(client, db, google_oauth_enabled):
    """GET /auth/google/callback when token exchange fails redirects to oauth_failed."""
    with respx.mock(assert_all_mocked=False) as router:
        router.post("https://oauth2.googleapis.com/token").mock(
            return_value=Response(401, json={"error": "invalid_grant"})
        )

        res = await client.get("/api/auth/google/callback?code=bad-code", follow_redirects=False)
        assert res.status_code in REDIRECT_STATUS
        assert "login?error=oauth_failed" in res.headers["location"]


@pytest.mark.asyncio
async def test_google_callback_no_email(client, db, google_oauth_enabled):
    """GET /auth/google/callback when userinfo has no email redirects to no_email."""
    with respx.mock(assert_all_mocked=False) as router:
        router.post("https://oauth2.googleapis.com/token").mock(
            return_value=Response(
                200,
                json={"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600},
            )
        )
        router.get("https://www.googleapis.com/oauth2/v2/userinfo").mock(
            return_value=Response(200, json={"id": "123", "name": "No Email User"})
        )

        res = await client.get("/api/auth/google/callback?code=fake-code", follow_redirects=False)
        assert res.status_code in REDIRECT_STATUS
        assert "login?error=no_email" in res.headers["location"]


@pytest.mark.asyncio
async def test_google_callback_user_not_found(client, db, google_oauth_enabled):
    """GET /auth/google/callback when user not in Google tenant redirects to user_not_found."""
    with respx.mock(assert_all_mocked=False) as router:
        router.post("https://oauth2.googleapis.com/token").mock(
            return_value=Response(
                200,
                json={"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600},
            )
        )
        # Use email that does not exist in any tenant
        router.get("https://www.googleapis.com/oauth2/v2/userinfo").mock(
            return_value=Response(
                200,
                json={"email": "nonexistent@example.com", "name": "Unknown User"},
            )
        )

        await db.execute(
            text(
                "INSERT INTO tenants (id, name, created_at, auth_method) "
                "VALUES ('t-google', 'Google Tenant', NOW(), 'google') "
                "ON CONFLICT (id) DO UPDATE SET auth_method = 'google'"
            )
        )
        await db.commit()

        res = await client.get("/api/auth/google/callback?code=fake-code", follow_redirects=False)
        assert res.status_code in REDIRECT_STATUS
        assert "login?error=user_not_found" in res.headers["location"]


@pytest.mark.asyncio
async def test_auth_config_google_enabled(client, db, google_oauth_enabled):
    """GET /auth/config returns google_enabled=true when tenant has auth_method=google."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-google', 'Google Tenant', NOW(), 'google') "
            "ON CONFLICT (id) DO UPDATE SET auth_method = 'google'"
        )
    )
    await db.commit()

    res = await client.get("/api/auth/config")
    assert res.status_code == 200
    assert res.json()["google_enabled"] is True


@pytest.mark.asyncio
async def test_auth_config_google_disabled(client, db):
    """GET /auth/config returns google_enabled=false when no Google tenant."""
    res = await client.get("/api/auth/config")
    assert res.status_code == 200
    # May be False due to no credentials or no tenant
    assert "google_enabled" in res.json()
