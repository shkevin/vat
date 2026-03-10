"""OAuth client credentials for ingest — token issuance and validation."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.core.config import get_settings

INGEST_OAUTH_ISSUER = "vat-ingest-oauth"
INGEST_OAUTH_ALGORITHM = "HS256"
INGEST_TOKEN_EXPIRE_HOURS = 1


def create_ingest_token(source_id: str, expire_hours: Optional[int] = None) -> str:
    """Create a JWT for ingest attribution. Token encodes source_id."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp_dt = now + timedelta(hours=expire_hours or INGEST_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": source_id,
        "usage": "ingest",
        "exp": int(exp_dt.timestamp()),
        "iat": int(now.timestamp()),
        "iss": INGEST_OAUTH_ISSUER,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=INGEST_OAUTH_ALGORITHM)


def decode_ingest_token(token: str) -> Optional[str]:
    """Decode ingest OAuth token. Returns source_id or None if invalid."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[INGEST_OAUTH_ALGORITHM],
            issuer=INGEST_OAUTH_ISSUER,
        )
        if payload.get("usage") != "ingest":
            return None
        return payload.get("sub")
    except JWTError:
        return None
