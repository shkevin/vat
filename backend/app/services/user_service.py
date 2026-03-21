"""User service — lookup by email/id for auth."""

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import AUTH_METHOD_GOOGLE, User


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
