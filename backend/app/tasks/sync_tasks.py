"""Celery tasks for sync worker."""

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import app
from app.core.config import get_settings
from app.services.linear_poll_service import poll_linear_for_updates
from app.services.sync_service import (
    backfill_tracker_corrections,
    backfill_unsynced_findings,
    link_linear_issues_to_findings,
    process_pending_sync_events,
    unlink_deleted_linear_issues,
)

logger = logging.getLogger(__name__)


async def _run_linear_poll(force: bool = False) -> dict:
    """Run Linear API poll. When force=True (manual sync), runs regardless of linear_poll_enabled."""
    settings = get_settings()
    if not force and not settings.linear_poll_enabled:
        return {
            "issues_fetched": 0,
            "comments_processed": 0,
            "descriptions_processed": 0,
            "errors": [],
        }
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            return await poll_linear_for_updates(db, force=force)
    finally:
        await engine.dispose()


async def _run_sync_batch(limit: int) -> int:
    """Process a batch of pending sync events. Used for parallel fan-out."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            return await process_pending_sync_events(db, limit=limit)
    finally:
        await engine.dispose()


async def _run_sync_worker(
    limit: int = 50,
    backfill_limit: int = 50,
    corrections_limit: int = 50,
    parallel_batches: int = 4,
) -> dict:
    """
    Async runner for process + backfill + corrections.
    Creates fresh engine/session per run to avoid "attached to different loop" when Celery forks.
    corrections_limit: enqueue update_issue for linked findings to push VAT state (labels, title, severity)
    to tracker — idempotent sync so tracker reflects VAT regardless of manual edits in tracker.
    Skips tracker backfill and corrections when tracker is not configured.
    """
    from app.api.settings import get_tracker_key, get_tracker_push_mode
    from app.services.credential_resolver import SettingsCredentialResolver

    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    resolver = SettingsCredentialResolver()
    try:
        async with session_factory() as db:
            unlinked = await unlink_deleted_linear_issues(db)
            if unlinked > 0:
                await db.commit()
            tracker_key = await get_tracker_key(db)
            creds = await resolver.get_tracker_credentials(db, tracker_key)
            tracker_configured = bool(creds.get("api_key") and creds.get("team_id"))
            linked, link_fetched = 0, 0
            if tracker_configured:
                push_mode = await get_tracker_push_mode(db)
                if push_mode == "groups":
                    link_result = await link_linear_issues_to_findings(
                        db, max_issues=500
                    )
                    linked = link_result.get("linked", 0)
                    link_fetched = link_result.get("fetched", 0)
                if linked > 0:
                    await db.commit()
                # Backfill before process so newly enqueued create_issue events are processed in same run
                corrections_enqueued = await backfill_tracker_corrections(
                    db, limit=corrections_limit
                )
                enqueued = await backfill_unsynced_findings(db, limit=backfill_limit)
            else:
                corrections_enqueued = 0
                enqueued = 0
            # Commit backfill events so parallel batch workers (or next run) can see them
            if enqueued > 0 or corrections_enqueued > 0:
                await db.commit()
            # Run parallel batches via asyncio.gather (Celery forbids result.get() inside a task)
            batch_limit = max(1, limit // parallel_batches)
            if parallel_batches <= 1:
                processed = await process_pending_sync_events(db, limit=limit)
            else:
                results = await asyncio.gather(
                    *[_run_sync_batch(batch_limit) for _ in range(parallel_batches)]
                )
                processed = sum(r or 0 for r in results)
            return {
                "processed": processed,
                "backfill_enqueued": enqueued,
                "corrections_enqueued": corrections_enqueued,
                "unlinked": unlinked,
                "linked": linked,
                "link_fetched": link_fetched,
            }
    finally:
        await engine.dispose()


@app.task(bind=True, name="app.tasks.sync_tasks.process_sync_queue")
def process_sync_queue(
    self,
    limit: int = 50,
    backfill_limit: int = 50,
    corrections_limit: int = 50,
    parallel_batches: int | None = None,
) -> dict:
    """
    Process pending sync events, backfill corrections (idempotent tracker updates), and unsynced findings.
    Runs via Beat (every 2 min) or triggered immediately on enqueue.
    Corrections ensure tracker issues reflect VAT state (labels, title, severity) even when edited in tracker.
    """
    if parallel_batches is None:
        parallel_batches = get_settings().celery_worker_concurrency
    try:
        return asyncio.run(
            _run_sync_worker(
                limit=limit,
                backfill_limit=backfill_limit,
                corrections_limit=corrections_limit,
                parallel_batches=parallel_batches,
            )
        )
    except Exception as e:
        logger.exception("Sync worker failed: %s", e)
        raise self.retry(exc=e, countdown=60, max_retries=3)


@app.task(bind=True, name="app.tasks.sync_tasks.poll_linear")
def poll_linear(self, force: bool = False) -> dict:
    """
    Poll Linear API for [VAT] blocks in comments and descriptions.
    Use when webhooks aren't configured. Uses same credentials as Linear settings.
    When force=True (manual sync), runs regardless of VAT_LINEAR_POLL_ENABLED.
    """
    try:
        return asyncio.run(_run_linear_poll(force=force))
    except Exception as e:
        logger.exception("Linear poll failed: %s", e)
        raise self.retry(exc=e, countdown=60, max_retries=2)


@app.task(bind=True, name="app.tasks.sync_tasks.reconcile_linear")
def reconcile_linear(self) -> dict:
    """
    Reconciliation job: poll Linear for [VAT] updates to catch missed webhooks.
    Runs on schedule when webhooks are configured (safety net). Uses force=True
    to bypass linear_poll_enabled. Idempotency prevents double-apply with webhooks.
    """
    try:
        return asyncio.run(_run_linear_poll(force=True))
    except Exception as e:
        logger.exception("Linear reconciliation failed: %s", e)
        raise self.retry(exc=e, countdown=300, max_retries=2)


def trigger_sync_worker(countdown: int = 2) -> None:
    """
    Trigger sync worker task. Call after enqueueing sync events.
    countdown=2 coalesces rapid enqueues (e.g. bulk update) into one run.
    """
    try:
        process_sync_queue.apply_async(countdown=countdown)
    except Exception as e:
        logger.warning("Failed to trigger sync worker (will run on next Beat): %s", e)
