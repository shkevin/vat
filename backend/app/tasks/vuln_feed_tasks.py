"""Scheduled vulnerability feed refresh tasks."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import app
from app.core.config import get_settings
from app.services.vuln_feeds import (
    mark_vuln_feed_refresh_finished,
    mark_vuln_feed_refresh_running,
    prune_feed_storage,
    refresh_enabled_feeds,
    release_vuln_feed_refresh_lock,
    try_acquire_vuln_feed_refresh_lock,
)

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
            acquired = await try_acquire_vuln_feed_refresh_lock(db)
            if not acquired:
                return {
                    "enabled": True,
                    "already_running": True,
                    "sources": [],
                    "stats": [],
                }
            try:
                await mark_vuln_feed_refresh_running(db, actor_id="system")
                await db.commit()
                result = await refresh_enabled_feeds(db, actor_id="system")
                await mark_vuln_feed_refresh_finished(
                    db,
                    status="completed",
                    actor_id="system",
                    message="Vulnerability feed refresh completed.",
                )
                await db.commit()
                return result
            except Exception as exc:
                await db.rollback()
                await mark_vuln_feed_refresh_finished(
                    db,
                    status="failed",
                    actor_id="system",
                    message=str(exc)[:500],
                )
                await db.commit()
                raise
            finally:
                await release_vuln_feed_refresh_lock(db)
    finally:
        await engine.dispose()


async def _run_vuln_feed_retention() -> dict:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            result = await prune_feed_storage(db, actor_id="system")
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


@app.task(bind=True, name="app.tasks.vuln_feed_tasks.run_vuln_feed_retention")
def run_vuln_feed_retention(self) -> dict:
    """Prune old vulnerability feed run history and stale records."""
    try:
        return asyncio.run(_run_vuln_feed_retention())
    except Exception as exc:
        logger.exception("Vulnerability feed retention failed: %s", exc)
        raise self.retry(exc=exc, countdown=300, max_retries=2)
