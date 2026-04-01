"""Scheduled vulnerability feed refresh tasks."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import app
from app.core.config import get_settings
from app.services.vuln_feeds import refresh_enabled_feeds

logger = logging.getLogger(__name__)


async def _run_vuln_feed_refresh() -> dict:
    settings = get_settings()
    if not settings.vuln_feeds_enabled:
        return {"enabled": False, "sources": [], "stats": []}
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            result = await refresh_enabled_feeds(db, actor_id="system")
            await db.commit()
            return result
    finally:
        await engine.dispose()


@app.task(bind=True, name="app.tasks.vuln_feed_tasks.run_vuln_feed_refresh")
def run_vuln_feed_refresh(self) -> dict:
    """Refresh keyless vulnerability feeds from public sources."""
    try:
        return asyncio.run(_run_vuln_feed_refresh())
    except Exception as exc:
        logger.exception("Vulnerability feed refresh failed: %s", exc)
        raise self.retry(exc=exc, countdown=300, max_retries=2)
