"""Auth API — local login, Google OAuth, JWT issuance."""

import base64
import hashlib
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.jwt import (
    create_oauth_exchange_code,
    create_oauth_state,
    create_token,
    decode_oauth_exchange_code,
    decode_oauth_state,
    decode_token,
)
from app.models.user import AUTH_METHOD_LOCAL, Tenant
from app.services.user_service import (
    perform_dummy_verify,
    get_google_tenant,
    get_user_by_email,
    get_user_by_email_in_google_tenant,
    get_user_by_id,
    verify_password,
)

router = APIRouter()
logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"

# Browser session cookie. httpOnly so XSS cannot read the JWT (the previous
# localStorage path was reachable from any DOM injection sink). Secure in
# production. SameSite=Lax allows the OAuth-callback redirect to land with
# the cookie attached on top-level navigations while still defeating most
# CSRF; a future step adds a CSRF token for state-changing requests as
# belt-and-suspenders.
SESSION_COOKIE_NAME = "vat-session"
CSRF_COOKIE_NAME = "vat-csrf"


def _set_session_cookie(response, token: str) -> None:
    """Attach the JWT as an httpOnly session cookie + a non-httpOnly CSRF
    companion. The CSRF cookie is the double-submit token the frontend
    echoes as ``X-VAT-CSRF`` on state-changing requests; the middleware
    verifies the header matches the cookie. SameSite=Lax already
    defeats most CSRF; this is belt-and-suspenders."""
    settings = get_settings()
    cookie_kwargs = {
        "max_age": settings.jwt_expire_hours * 3600,
        "secure": settings.env == "production",
        "samesite": "lax",
        "path": "/",
    }
    response.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, **cookie_kwargs
    )
    # CSRF token is intentionally NOT httpOnly — the frontend reads it.
    # Knowing the token is fine: an attacker cross-origin can't read the
    # cookie (Lax + same-origin policy), so they can't construct a
    # matching X-VAT-CSRF header.
    response.set_cookie(
        CSRF_COOKIE_NAME, secrets.token_urlsafe(32), httponly=False, **cookie_kwargs
    )


def _clear_session_cookie(response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


class AuthConfigResponse(BaseModel):
    google_enabled: bool
    """True when VAT_GOOGLE_CLIENT_ID, VAT_GOOGLE_CLIENT_SECRET are set and a tenant has auth_method=google."""


class ExchangeCodeRequest(BaseModel):
    code: str


class ExchangeCodeResponse(BaseModel):
    token: str
    user: dict


@router.post("/exchange-code", response_model=ExchangeCodeResponse)
async def exchange_code(body: ExchangeCodeRequest, response: Response):
    """
    Exchange OAuth callback code for JWT. Code is short-lived (60s), single-use.
    Called by frontend after redirect from Google OAuth callback.

    Sets an httpOnly session cookie alongside the JSON token. New frontend
    code should rely on the cookie; legacy code reading the JSON token
    keeps working during the migration.
    """
    token = decode_oauth_exchange_code(body.code)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code",
        )
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token",
        )
    _set_session_cookie(response, token)
    return ExchangeCodeResponse(
        token=token,
        user={
            "id": payload.get("user_id", payload.get("sub", "")),
            "email": payload.get("sub", ""),
            "role": payload.get("role", "reviewer"),
            "tenant_id": payload.get("tenant_id"),
        },
    )


@router.post("/logout")
async def logout(response: Response):
    """Clear the session cookie. Returns 204; the client should also
    purge any in-memory or legacy localStorage token alongside this.
    """
    _clear_session_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me")
async def me(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return the current user when a session is present.

    Used by the frontend to bootstrap state on page load when the JWT
    lives only in the httpOnly cookie. Resolves through the standard
    auth path with both the Authorization header AND the vat-session
    cookie threaded through, so cookie-only sessions resolve correctly.
    """
    from app.core.auth import SESSION_COOKIE_NAME, _resolve_user_context

    auth_header = request.headers.get("Authorization")
    creds = None
    if auth_header and auth_header.lower().startswith("bearer "):
        from fastapi.security import HTTPAuthorizationCredentials

        creds = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=auth_header[7:]
        )
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    ctx, ok = await _resolve_user_context(
        creds, None, None, db, session_cookie=session_cookie
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    return {
        "id": ctx.user_id,
        "email": ctx.email,
        "role": ctx.role,
        "tenant_id": ctx.tenant_id,
    }


@router.get("/config", response_model=AuthConfigResponse)
async def auth_config(db: AsyncSession = Depends(get_db)):
    """Return which IdP options are available. Public, no auth required."""
    settings = get_settings()
    has_creds = bool(settings.google_client_id and settings.google_client_secret)
    tenant = await get_google_tenant(db) if has_creds else None
    return AuthConfigResponse(google_enabled=bool(tenant))


GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    user: dict
    """User object: id, email, role, tenant_id."""
    token: str
    """JWT for Authorization: Bearer."""


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Local login with username/password.
    Only works for tenants with auth_method=local. Returns user + JWT.
    """
    if not body.username.strip() or not body.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username and password required",
        )
    ident = body.username.strip()
    user = await get_user_by_id(db, ident)
    if not user:
        # Allow email as well as user id (seed admin uses id "admin", email admin@vat.local).
        user = await get_user_by_email(db, ident)
    if not user:
        # Spend the same ~100ms a real verify would so an attacker can't
        # distinguish "no such user" from "wrong password" by latency.
        perform_dummy_verify()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    # Enforce tenant auth_method=local
    if user.tenant_id:
        result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
        tenant = result.scalar_one_or_none()
        if tenant and tenant.auth_method != AUTH_METHOD_LOCAL:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Use Sign in with Google for this account",
            )
    token = create_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        role=user.role,
    )
    _set_session_cookie(response, token)
    return LoginResponse(
        user={
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "tenant_id": user.tenant_id,
        },
        token=token,
    )


OAUTH_STATE_COOKIE = "vat-oauth-state"
OAUTH_STATE_TTL_SECONDS = 300


def _make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256) per RFC 7636."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@router.get("/google/authorize")
async def google_authorize(
    db: AsyncSession = Depends(get_db),
):
    """Redirect to Google OAuth. Requires VAT_GOOGLE_CLIENT_ID and a tenant with auth_method=google.

    Adds CSRF protection via a signed ``state`` (echoed by Google, verified
    on callback) plus a browser-binding httpOnly cookie that must match.
    Adds PKCE (S256) so an attacker who intercepts the authorization code
    still cannot exchange it without the code_verifier sealed in the cookie.
    """
    settings = get_settings()
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth not configured",
        )
    tenant = await get_google_tenant(db)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No tenant configured for Google sign-in",
        )
    redirect_uri = f"{settings.public_url.rstrip('/')}/api/auth/google/callback"
    code_verifier, code_challenge = _make_pkce_pair()
    state = create_oauth_state(code_verifier, ttl_seconds=OAUTH_STATE_TTL_SECONDS)
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    response = RedirectResponse(url=url)
    # SameSite=Lax is required for the cross-site GET callback to send the
    # cookie back. Secure requires HTTPS in production (the prod-startup
    # gate already enforces https:// origins).
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        state,
        max_age=OAUTH_STATE_TTL_SECONDS,
        httponly=True,
        secure=settings.env == "production",
        samesite="lax",
        path="/api/auth/google/callback",
    )
    return response


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    state_cookie: str | None = Cookie(default=None, alias=OAUTH_STATE_COOKIE),
    db: AsyncSession = Depends(get_db),
):
    """Handle Google OAuth callback. Verify state + PKCE, exchange code, issue JWT, redirect to frontend."""
    settings = get_settings()
    frontend_url = settings.frontend_url or settings.public_url.replace(
        ":8000", ":3000"
    ).rstrip("/")

    if error:
        logger.warning("Google OAuth error: %s", error)
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_denied")
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code"
        )
    # CSRF defense: state must be present, must be a valid signed token, and
    # must match the cookie set by /authorize. Either side missing → reject.
    if not state or not state_cookie or state != state_cookie:
        logger.warning("Google OAuth state/cookie mismatch")
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_state")
    state_payload = decode_oauth_state(state)
    if not state_payload:
        logger.warning("Google OAuth state failed signature/expiry check")
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_state")
    code_verifier = state_payload.get("cv")
    if not code_verifier:
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_state")

    redirect_uri = f"{settings.public_url.rstrip('/')}/api/auth/google/callback"
    # Bound the upstream call so a stalled Google response cannot pin a
    # request worker open indefinitely.
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_res = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if token_res.status_code != 200:
        logger.warning("Google token exchange failed: %s", token_res.status_code)
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_failed")
    token_data = token_res.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_failed")
    async with httpx.AsyncClient(timeout=10.0) as client:
        userinfo_res = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if userinfo_res.status_code != 200:
        logger.warning("Google userinfo failed: %s", userinfo_res.status_code)
        return _clear_state_redirect(f"{frontend_url}/login?error=oauth_failed")
    userinfo = userinfo_res.json()
    email = userinfo.get("email")
    if not email:
        return _clear_state_redirect(f"{frontend_url}/login?error=no_email")
    user = await get_user_by_email_in_google_tenant(db, email)
    if not user:
        logger.warning("Google user not found in Google tenant: %s", email)
        return _clear_state_redirect(f"{frontend_url}/login?error=user_not_found")
    auth_token = create_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        role=user.role,
    )
    # Use one-time code instead of token in URL to avoid logging/referrer exposure
    exchange_code = create_oauth_exchange_code(auth_token)
    return _clear_state_redirect(f"{frontend_url}/login?code={exchange_code}")


def _clear_state_redirect(url: str) -> RedirectResponse:
    """Redirect that also clears the OAuth state cookie. Always used on
    callback exits so a stale state doesn't survive into the next attempt."""
    response = RedirectResponse(url=url)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth/google/callback")
    return response
