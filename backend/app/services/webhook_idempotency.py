"""Webhook idempotency — prevent duplicate processing on retries."""

import hashlib
import json
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook_event import WebhookEvent

logger = logging.getLogger(__name__)


def compute_idempotency_key(source: str, event_type: str, *parts: str) -> str:
    """Compute idempotency key from source, event type, and identifying parts."""
    raw = f"{source}:{event_type}:" + ":".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


async def is_duplicate_webhook(db: AsyncSession, idempotency_key: str) -> bool:
    """Return True if we've already processed this webhook (duplicate)."""
    r = await db.execute(select(WebhookEvent).where(WebhookEvent.idempotency_key == idempotency_key))
    return r.scalar_one_or_none() is not None


async def record_webhook_processed(
    db: AsyncSession,
    idempotency_key: str,
    source: str,
    event_type: Optional[str] = None,
    payload: Optional[dict] = None,
    result: Optional[dict] = None,
) -> None:
    """Record that we processed this webhook (for idempotency)."""
    payload_hash = None
    if payload is not None:
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:64]
    db.add(
        WebhookEvent(
            idempotency_key=idempotency_key,
            source=source,
            event_type=event_type,
            payload_hash=payload_hash,
            result=result,
        )
    )
