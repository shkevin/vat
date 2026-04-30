"""OAuth 2.0 client credentials grant for ingest — POST /api/oauth/token."""

from fastapi import APIRouter, Depends, Form, HTTPException

from app.core.config import get_settings
from app.core.database import get_db
from app.core.oauth import create_ingest_token
from app.core.rate_limit import is_locked, record_failure, reset
from app.services.oauth_clients import validate_oauth_client
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


def _lockout_key(client_id: str) -> str:
    return f"vat:oauth_token:lockout:{client_id}"


@router.post("/token")
async def post_token(
    grant_type: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth 2.0 client credentials grant.
    Accepts application/x-www-form-urlencoded. Returns access_token for ingest.

    Brute-force lockout: after N failed exchanges for the same
    ``client_id`` within the configured window, further attempts return
    429 until the window expires. Counter is per-``client_id`` so an
    attacker burning attempts on one id doesn't lock out others. Backed
    by Redis (Celery broker); fail-open if Redis is unreachable so an
    infra outage cannot block legitimate clients.
    """
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400, detail="grant_type must be client_credentials"
        )
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=400, detail="client_id and client_secret required"
        )

    settings = get_settings()
    lockout_key = _lockout_key(client_id)
    if await is_locked(lockout_key, settings.oauth_token_lockout_threshold):
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(settings.oauth_token_lockout_window_sec)},
        )

    result = await validate_oauth_client(db, client_id, client_secret)
    if not result:
        await record_failure(lockout_key, settings.oauth_token_lockout_window_sec)
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Successful auth — clear the bucket so a legitimate client returning
    # after some flaky tries doesn't carry a primed counter.
    await reset(lockout_key)

    source_id, _ = result
    token = create_ingest_token(source_id)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
