"""User service — lookup by email/id for auth."""

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import AUTH_METHOD_GOOGLE, User

# Constant-time bcrypt cost on the not-found path. Generated once at import
# time so the dummy verify takes the same ~100ms as a real one regardless of
# whether the username exists. Used by ``perform_dummy_verify``.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(
    b"vat-dummy-not-a-real-password", bcrypt.gensalt()
)


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    """Look up user by id. Returns None if not found."""
    if not user_id or not user_id.strip():
        return None
    result = await db.execute(select(User).where(User.id == user_id.strip()))
    return result.scalar_one_or_none()


def verify_password(plain: str, password_hash: str | None) -> bool:
    """Verify plain password against hash. Returns False if hash is None."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def perform_dummy_verify() -> None:
    """Run a bcrypt verify against a precomputed dummy hash so the user-not-found
    login path takes roughly the same wall time as a real verify. Result is
    discarded; this is purely for timing parity to defeat username enumeration.
    """
    try:
        bcrypt.checkpw(b"vat-dummy-not-a-real-password", _DUMMY_PASSWORD_HASH)
    except Exception:
        # bcrypt failures are silent — the goal is to spend CPU time, not to
        # surface errors. The real auth check (or 401) handles the response.
        pass


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Look up user by email (case-insensitive). Returns None if not found."""
    if not email or not email.strip():
        return None
    normalized = email.strip().lower()
    result = await db.execute(select(User).where(User.email.ilike(normalized)))
    return result.scalar_one_or_none()


async def get_user_by_email_in_google_tenant(
    db: AsyncSession, email: str
) -> User | None:
    """Look up user by email where tenant has auth_method=google. For Google OAuth callback."""
    if not email or not email.strip():
        return None
    from app.models.user import Tenant

    normalized = email.strip().lower()
    result = await db.execute(
        select(User)
        .join(Tenant, User.tenant_id == Tenant.id)
        .where(User.email.ilike(normalized), Tenant.auth_method == AUTH_METHOD_GOOGLE)
    )
    return result.scalar_one_or_none()


async def get_google_tenant(db: AsyncSession):
    """Get first tenant with auth_method=google. Returns Tenant or None."""
    from app.models.user import Tenant

    result = await db.execute(
        select(Tenant).where(Tenant.auth_method == AUTH_METHOD_GOOGLE).limit(1)
    )
    return result.scalar_one_or_none()
