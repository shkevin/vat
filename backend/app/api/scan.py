"""Scan support API — known-digest projection for event-driven scan dedup.

Phase 0 of docs/implementation-plan-event-driven-scanning.md. Read-only; the
operator polls this to dedup against VAT's source of truth and survive restarts.
"""

import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.ingest_auth import get_ingest_source
from app.services.scan_digests import known_image_digests

router = APIRouter()


@router.get("/known-digests")
async def get_known_digests(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _src: tuple = Depends(get_ingest_source),
):
    """Image digests VAT already has findings/SBOMs for — the operator's dedup set.

    Flat list (cardinality is small) plus a content-based ``ETag`` so the operator
    can poll cheaply: ``If-None-Match`` returns 304 when the digest set is unchanged.
    """
    digests = await known_image_digests(db)
    etag = '"' + hashlib.sha256("\n".join(digests).encode()).hexdigest()[:32] + '"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return {
        "digests": digests,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }
