"""Scheduled audit ledger tasks (Celery Beat)."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import app
from app.core.config import get_settings
from app.services.audit_events import create_daily_checkpoint

logger = logging.getLogger(__name__)


async def _run_daily_checkpoint() -> dict:
    settings = get_settings()
    if not settings.audit_daily_checkpoint_enabled:
        return {"skipped": True, "reason": "audit_daily_checkpoint_enabled=false"}

    yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
    checkpoint_date = yesterday.isoformat()
    retention = settings.audit_checkpoint_retention_class

    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            cp = await create_daily_checkpoint(
                db,
                checkpoint_date=checkpoint_date,
                retention_class=retention,
            )
            await db.commit()
            return {
                "checkpoint_date": cp.checkpoint_date,
                "retention_class": cp.retention_class,
                "event_count": cp.event_count,
                "anchor_hash": cp.anchor_hash,
            }
    finally:
        await engine.dispose()


@app.task(bind=True, name="app.tasks.audit_tasks.run_daily_audit_checkpoint")
def run_daily_audit_checkpoint(self) -> dict:
    """Anchor the previous UTC calendar day in audit_ledger_checkpoints (idempotent)."""
    try:
        return asyncio.run(_run_daily_checkpoint())
    except Exception as e:
        logger.exception("Daily audit checkpoint failed: %s", e)
        raise self.retry(exc=e, countdown=300, max_retries=2)
