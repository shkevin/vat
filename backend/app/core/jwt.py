"""JWT issuance and validation for VAT auth."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.core.config import get_settings

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "vat"


def create_token(
    user_id: str,
    email: str,
    tenant_id: Optional[str],
    role: str,
    expire_hours: Optional[int] = None,
) -> str:
    """Create a signed JWT for the given user."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp_dt = now + timedelta(hours=expire_hours or settings.jwt_expire_hours)
    payload = {
        "sub": email,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": int(exp_dt.timestamp()),
        "iat": int(now.timestamp()),
        "iss": JWT_ISSUER,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT. Returns payload dict or None if invalid."""
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
    except JWTError:
        return None


OAUTH_EXCHANGE_ISSUER = "vat-oauth-exchange"


def create_oauth_exchange_code(token: str) -> str:
    """Create a short-lived JWT containing the auth token for OAuth callback redirect.
    Avoids putting the token in the URL. Expires in 60 seconds."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "grant": token,
        "usage": "oauth_exchange",
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": OAUTH_EXCHANGE_ISSUER,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def decode_oauth_exchange_code(code: str) -> Optional[str]:
    """Decode OAuth exchange code, return grant token or None if invalid/expired."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            code,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=OAUTH_EXCHANGE_ISSUER,
        )
        return payload.get("grant")
    except JWTError:
        return None
