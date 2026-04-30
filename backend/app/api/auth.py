"""Auth API — local login, Google OAuth, JWT issuance."""

import logging
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.jwt import (
    create_oauth_exchange_code,
    create_token,
    decode_oauth_exchange_code,
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


class AuthConfigResponse(BaseModel):
    google_enabled: bool
    """True when VAT_GOOGLE_CLIENT_ID, VAT_GOOGLE_CLIENT_SECRET are set and a tenant has auth_method=google."""


class ExchangeCodeRequest(BaseModel):
    code: str


class ExchangeCodeResponse(BaseModel):
    token: str
    user: dict


@router.post("/exchange-code", response_model=ExchangeCodeResponse)
async def exchange_code(body: ExchangeCodeRequest):
    """
    Exchange OAuth callback code for JWT. Code is short-lived (60s), single-use.
    Called by frontend after redirect from Google OAuth callback.
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
    return ExchangeCodeResponse(
        token=token,
        user={
            "id": payload.get("user_id", payload.get("sub", "")),
            "email": payload.get("sub", ""),
            "role": payload.get("role", "reviewer"),
            "tenant_id": payload.get("tenant_id"),
        },
    )


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
    return LoginResponse(
        user={
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "tenant_id": user.tenant_id,
        },
        token=token,
    )


@router.get("/google/authorize")
async def google_authorize(
    db: AsyncSession = Depends(get_db),
):
    """Redirect to Google OAuth. Requires VAT_GOOGLE_CLIENT_ID and a tenant with auth_method=google."""
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
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
    }
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url=url)


@router.get("/google/callback")
async def google_callback(
    code: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Handle Google OAuth callback. Exchange code for tokens, lookup user, issue JWT, redirect to frontend."""
    settings = get_settings()
    frontend_url = settings.frontend_url or settings.public_url.replace(
        ":8000", ":3000"
    ).rstrip("/")

    if error:
        logger.warning("Google OAuth error: %s", error)
        return RedirectResponse(url=f"{frontend_url}/login?error=oauth_denied")
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code"
        )
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
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if token_res.status_code != 200:
        logger.warning("Google token exchange failed: %s", token_res.status_code)
        return RedirectResponse(url=f"{frontend_url}/login?error=oauth_failed")
    token_data = token_res.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return RedirectResponse(url=f"{frontend_url}/login?error=oauth_failed")
    async with httpx.AsyncClient(timeout=10.0) as client:
        userinfo_res = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if userinfo_res.status_code != 200:
        logger.warning("Google userinfo failed: %s", userinfo_res.status_code)
        return RedirectResponse(url=f"{frontend_url}/login?error=oauth_failed")
    userinfo = userinfo_res.json()
    email = userinfo.get("email")
    if not email:
        return RedirectResponse(url=f"{frontend_url}/login?error=no_email")
    user = await get_user_by_email_in_google_tenant(db, email)
    if not user:
        logger.warning("Google user not found in Google tenant: %s", email)
        return RedirectResponse(url=f"{frontend_url}/login?error=user_not_found")
    auth_token = create_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        role=user.role,
    )
    # Use one-time code instead of token in URL to avoid logging/referrer exposure
    exchange_code = create_oauth_exchange_code(auth_token)
    return RedirectResponse(url=f"{frontend_url}/login?code={exchange_code}")
