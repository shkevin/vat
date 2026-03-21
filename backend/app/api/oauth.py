"""OAuth 2.0 client credentials grant for ingest — POST /api/oauth/token."""

from fastapi import APIRouter, Depends, Form, HTTPException

from app.core.database import get_db
from app.core.oauth import create_ingest_token
from app.services.oauth_clients import validate_oauth_client
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


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
    """
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400, detail="grant_type must be client_credentials"
        )
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=400, detail="client_id and client_secret required"
        )

    result = await validate_oauth_client(db, client_id, client_secret)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    source_id, _ = result
    token = create_ingest_token(source_id)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
