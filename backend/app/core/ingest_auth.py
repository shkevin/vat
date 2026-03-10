"""Ingest API authentication — API key and OAuth token validation. Design doc 2026-02-24."""

from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.oauth import decode_ingest_token
from app.services.ingest_keys import validate_key

bearer_scheme = HTTPBearer(auto_error=False)


def _extract_key(
    authorization: Optional[HTTPAuthorizationCredentials],
    x_vat_api_key: Optional[str],
) -> Optional[str]:
    """Extract API key from Authorization Bearer or X-VAT-API-Key header."""
    if x_vat_api_key and x_vat_api_key.strip():
        return x_vat_api_key.strip()
    if authorization and authorization.credentials:
        return authorization.credentials.strip()
    return None


async def get_ingest_source(
    authorization: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_vat_api_key: Optional[str] = Header(None, alias="X-VAT-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> tuple[Optional[str], Optional[str]]:
    """
    Validate ingest API key or OAuth token and resolve source.
    Returns (source_name, user_attribution).
    - source_name: When key/token valid and maps to sourceId, use it. Else None (caller uses body/query).
    - user_attribution: For audit (e.g. "ingest:trivy-ci" or "api-key").
    Raises 401 if auth required and invalid/missing.
    """
    key = _extract_key(authorization, x_vat_api_key)
    settings = get_settings()

    if not key:
        if settings.require_ingest_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Ingest requires API key. Use Authorization: Bearer <key> or X-VAT-API-Key.",
            )
        return (None, None)

    # Env fallback — use "api" as source_id for parser lookup
    if settings.ingest_api_key and key.strip() == settings.ingest_api_key.strip():
        return ("api", "api-key")

    # API key (vat_ prefix)
    if key.strip().startswith("vat_"):
        result = await validate_key(db, key)
        if result:
            source_id, user = result
            return (source_id, user)
    else:
        # OAuth token (JWT from POST /api/oauth/token)
        source_id = decode_ingest_token(key)
        if source_id:
            return (source_id, f"ingest:{source_id}")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key or token",
    )
