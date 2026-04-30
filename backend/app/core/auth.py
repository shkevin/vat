"""Authentication — JWT, OAuth2, API key. PRD §7.3, §8.1, §9.2. RBAC v2.0.

Attestation and audit entries use authenticated identity:
- JWT Bearer: ctx.email (from 'sub' claim) or ctx.raw_identity
- OAuth2/SAML: Same flow — IdP returns claims, we store in JWT
- All reviewer actions (update, archive, revert, attestation) require get_current_user_context
  and pass user=ctx.email or ctx.raw_identity to findings_service
- Webhooks (Aikido, Linear) use system attribution; tracker decisions are posted by VAT
"""

from typing import Any, Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import false as sql_false
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.jwt import decode_token
from app.core.log_context import set_tenant_id, set_user_id
from app.schemas.auth import UserContext
from app.services.user_service import get_user_by_email

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def _identity_from_headers(
    authorization: Optional[HTTPAuthorizationCredentials],
    x_api_key: Optional[str],
    x_vat_user: Optional[str],
) -> str:
    """Extract identity string from auth headers (for audit)."""
    if x_vat_user and x_vat_user.strip():
        return x_vat_user.strip()[:128]
    if x_api_key:
        return "api-key"
    if authorization and authorization.credentials:
        cred = authorization.credentials
        return cred[:20] + "..." if len(cred) > 20 else cred
    return "anonymous"


async def _resolve_user_context(
    authorization: Optional[HTTPAuthorizationCredentials],
    x_api_key: Optional[str],
    x_vat_user: Optional[str],
    db: AsyncSession,
) -> tuple[UserContext, bool]:
    """
    Resolve user context. Returns (context, is_authenticated).
    X-VAT-User only used when VAT_ALLOW_DEV_HEADERS=true (dev/testing only).
    """
    # 1. JWT Bearer token — validate and use claims directly
    if authorization and authorization.credentials:
        payload = decode_token(authorization.credentials)
        if payload:
            return (
                UserContext(
                    user_id=payload.get("user_id", payload.get("sub", "")),
                    email=payload.get("sub", ""),
                    tenant_id=payload.get("tenant_id"),
                    role=payload.get("role", "reviewer"),
                    raw_identity=payload.get("sub", ""),
                    cross_tenant=False,
                ),
                True,
            )

        # 2. Admin API key (vat_ prefix) — grants admin role for automation.
        # Tenant binding from the key entry is authoritative: a key bound to a
        # tenant produces a tenant-scoped context; cross-tenant requires the
        # key to be explicitly created with cross_tenant=True.
        from app.services.admin_keys import resolve_admin_key

        resolved = await resolve_admin_key(db, authorization.credentials)
        if resolved is not None:
            return (
                UserContext(
                    user_id=f"admin-key:{resolved.key_id}",
                    email="admin-api-key@vat.local",
                    tenant_id=resolved.tenant_id,
                    role="admin",
                    raw_identity=f"admin-api-key:{resolved.key_id}",
                    cross_tenant=resolved.cross_tenant,
                ),
                True,
            )

    identity = _identity_from_headers(authorization, x_api_key, x_vat_user)

    # 2. X-VAT-User: only when explicitly enabled (dev/testing)
    settings = get_settings()
    if settings.allow_dev_headers and x_vat_user and "@" in x_vat_user.strip():
        user = await get_user_by_email(db, x_vat_user.strip())
        if user:
            return (
                UserContext(
                    user_id=user.id,
                    email=user.email,
                    tenant_id=user.tenant_id,
                    role=user.role,
                    raw_identity=x_vat_user.strip(),
                    cross_tenant=False,
                ),
                True,
            )

    # 3. Unauthenticated
    return (
        UserContext(
            user_id="",
            email="",
            tenant_id=None,
            role="read_only",
            raw_identity=identity,
            cross_tenant=False,
        ),
        False,
    )


async def get_current_user_context(
    authorization: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Depends(api_key_header),
    x_vat_user: Optional[str] = Header(None, alias="X-VAT-User"),
    db: AsyncSession = Depends(get_db),
) -> UserContext:
    """
    Resolve current user for RBAC. Raises 401 if unauthenticated.
    Use get_user_context_optional for endpoints that allow anonymous (e.g. SBOM audit).
    """
    ctx, is_authenticated = await _resolve_user_context(
        authorization, x_api_key, x_vat_user, db
    )
    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    # Bind to LogContext so subsequent log lines on this request carry
    # tenant/user attribution.
    set_tenant_id(ctx.tenant_id)
    set_user_id(ctx.user_id or None)
    return ctx


async def get_user_context_optional(
    authorization: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Depends(api_key_header),
    x_vat_user: Optional[str] = Header(None, alias="X-VAT-User"),
    db: AsyncSession = Depends(get_db),
) -> UserContext:
    """
    Resolve user context without raising. Returns anonymous context if unauthenticated.
    Use for endpoints that allow optional audit attribution (e.g. SBOM upload).
    """
    ctx, _ = await _resolve_user_context(authorization, x_api_key, x_vat_user, db)
    set_tenant_id(ctx.tenant_id)
    set_user_id(ctx.user_id or None)
    return ctx


async def get_current_user(
    ctx: UserContext = Depends(get_current_user_context),
) -> str:
    """Legacy: return identity string for audit. Use get_current_user_context for RBAC."""
    return ctx.email or ctx.raw_identity


async def get_current_user_optional(
    ctx: UserContext = Depends(get_user_context_optional),
) -> str:
    """Return identity string for audit. Never raises; anonymous returns 'anonymous'."""
    return ctx.email or ctx.raw_identity


async def require_reviewer(
    ctx: UserContext = Depends(get_current_user_context),
) -> UserContext:
    """
    RBAC: require reviewer or admin role for write operations.
    Raises 403 if role is read_only.
    """
    if ctx.role not in ("admin", "reviewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: reviewer or admin role required",
        )
    return ctx


async def require_admin(
    ctx: UserContext = Depends(get_current_user_context),
) -> UserContext:
    """RBAC: require admin role for tenant/user management."""
    if ctx.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return ctx


def tenant_filter(model: Any, ctx: UserContext) -> Any:
    """Return a SQLAlchemy WHERE clause that scopes ``model`` to ``ctx``'s tenant.

    Fail-closed semantics:
    - ``cross_tenant=True`` callers (admin keys bound to all tenants) get a
      pass-through condition that does not filter.
    - tenant-scoped callers get ``model.tenant_id == ctx.tenant_id``.
    - callers with neither (``tenant_id=None`` and ``cross_tenant=False``) get
      a literal-false condition so the query returns no rows. Returning
      everything here is what the previous ``IS NULL`` bypass did, and it
      leaked data across tenants.

    Use as ``q = q.where(tenant_filter(Finding, ctx))``.
    """
    if ctx.cross_tenant:
        # No tenant constraint — caller is explicitly authorized cross-tenant.
        return model.tenant_id.is_(model.tenant_id) | model.tenant_id.is_(None)
    if ctx.tenant_id is None:
        # Fail closed.
        return sql_false()
    return model.tenant_id == ctx.tenant_id
