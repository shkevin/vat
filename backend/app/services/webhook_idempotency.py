"""Webhook idempotency — prevent duplicate processing on retries.

The idempotency claim must be atomic with respect to other concurrent webhook
deliveries. Postgres ``INSERT ... ON CONFLICT (idempotency_key) DO NOTHING
RETURNING id`` gives us "first writer wins" semantics in a single round-trip:
the caller knows whether it claimed the slot or whether another delivery beat
it. Side effects must be applied only when ``claim_webhook`` returns True
within the same transaction so a rollback also releases the claim.
"""

import hashlib
import json
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook_event import WebhookEvent

logger = logging.getLogger(__name__)


def compute_idempotency_key(source: str, event_type: str, *parts: str) -> str:
    """Compute idempotency key from source, event type, and identifying parts."""
    raw = f"{source}:{event_type}:" + ":".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def _payload_hash(payload: Optional[dict]) -> Optional[str]:
    if payload is None:
        return None
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()[:64]


async def claim_webhook(
    db: AsyncSession,
    idempotency_key: str,
    source: str,
    event_type: Optional[str] = None,
    payload: Optional[dict] = None,
    result: Optional[dict] = None,
) -> bool:
    """Atomically claim ``idempotency_key`` for processing.

    Returns True when this caller is the first to claim the key (and must
    therefore perform the side effect). Returns False when another delivery
    has already claimed it (the caller should treat the request as a
    duplicate).

    Callers must use this within the same transaction as their side effect:
    a rollback after a successful claim will release it, allowing a future
    retry to legitimately re-claim.
    """
    stmt = (
        pg_insert(WebhookEvent)
        .values(
            idempotency_key=idempotency_key,
            source=source,
            event_type=event_type,
            payload_hash=_payload_hash(payload),
            result=result,
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
        .returning(WebhookEvent.id)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none() is not None


async def is_duplicate_webhook(db: AsyncSession, idempotency_key: str) -> bool:
    """Read-only check. Subject to TOCTOU under concurrency — prefer
    ``claim_webhook`` when guarding a side effect.
    """
    r = await db.execute(
        select(WebhookEvent).where(WebhookEvent.idempotency_key == idempotency_key)
    )
    return r.scalar_one_or_none() is not None


async def record_webhook_processed(
    db: AsyncSession,
    idempotency_key: str,
    source: str,
    event_type: Optional[str] = None,
    payload: Optional[dict] = None,
    result: Optional[dict] = None,
) -> None:
    """Best-effort record of a processed webhook.

    Uses ON CONFLICT DO NOTHING so a re-record (or a paired call after
    ``claim_webhook``) is harmless. Prefer ``claim_webhook`` at the entry of
    a side-effect path; reserve this helper for paths that need to record
    completion metadata after the work has finished.
    """
    stmt = (
        pg_insert(WebhookEvent)
        .values(
            idempotency_key=idempotency_key,
            source=source,
            event_type=event_type,
            payload_hash=_payload_hash(payload),
            result=result,
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
    )
    await db.execute(stmt)
