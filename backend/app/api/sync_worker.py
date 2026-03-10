"""Sync worker API — manual trigger and backfill. Celery Beat handles periodic runs."""

import logging

from fastapi import APIRouter, Depends

from app.core.auth import require_admin
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.linear_poll_service import poll_linear_for_updates
from app.services.sync_service import (
    backfill_tracker_corrections,
    backfill_unsynced_findings,
    get_sync_status,
    link_linear_issues_to_findings,
    process_pending_sync_events,
    reset_failed_tracker_events,
    unlink_deleted_linear_issues,
)
from app.tasks.sync_tasks import poll_linear, process_sync_queue, trigger_sync_worker
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/status")
async def sync_status(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Diagnostic sync status: total open findings, unlinked count, unique groups to create,
    pending create_issue events. Use to understand how many Linear issues should be created.
    """
    return await get_sync_status(db)


@router.post("")
async def sync_vat_linear(
    use_celery: bool = True,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Full sync between VAT and Linear. Runs in order:
    0. Unlink findings whose Linear issues were deleted (so they can be recreated)
    1. Link existing Linear issues to VAT findings (by CVE ID)
    2. Reset failed sync events for retry
    3. Backfill corrections (enqueue update_issue for linked findings to fix labels, title, severity)
    4. Process pending sync queue (create/update issues)
    5. Backfill unsynced findings (enqueue create_issue)
    6. Poll Linear for [VAT] blocks (inbound: status, justification, compensating controls)
    Triggers Celery worker for async processing when use_celery=true.
    """
    unlinked = await unlink_deleted_linear_issues(db)
    link_result = await link_linear_issues_to_findings(db, max_issues=500)
    reset_count = await reset_failed_tracker_events(db, "linear")
    corrections_enqueued = await backfill_tracker_corrections(db, limit=50)
    await db.commit()

    if use_celery:
        try:
            # Higher limits for manual sync so one click pushes more findings
            process_sync_queue.apply_async(kwargs={"limit": 100, "backfill_limit": 200})
            # Always poll on manual sync so "Sync" pulls [VAT] updates from Linear (bidirectional)
            poll_linear.apply_async(kwargs={"force": True})
            poll_result = {"poll_dispatched": True}
            return {
                "dispatched": True,
                "unlinked": unlinked,
                "linked": link_result.get("linked", 0),
                "fetched": link_result.get("fetched", 0),
                "reset": reset_count,
                "corrections_enqueued": corrections_enqueued,
                **poll_result,
            }
        except Exception as e:
            logger.warning("Celery unavailable, running inline: %s", e)

    processed = await process_pending_sync_events(db, limit=100)
    enqueued = await backfill_unsynced_findings(db, limit=200)
    if enqueued > 0 or reset_count > 0:
        trigger_sync_worker(countdown=1)

    # Always poll on manual sync so "Sync" pulls [VAT] updates from Linear (bidirectional)
    poll_result = await poll_linear_for_updates(db, force=True)

    return {
        "processed": processed,
        "backfill_enqueued": enqueued,
        "corrections_enqueued": corrections_enqueued,
        "unlinked": unlinked,
        "linked": link_result.get("linked", 0),
        "fetched": link_result.get("fetched", 0),
        "reset": reset_count,
        **poll_result,
    }


@router.post("/process")
async def process_sync_queue_api(
    limit: int = 50,
    backfill_limit: int = 50,
    use_celery: bool = True,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Process pending sync events and backfill unsynced findings.
    - use_celery=true (default): dispatch to Celery worker (non-blocking)
    - use_celery=false: run inline (for debugging when Celery unavailable)
    """
    if use_celery:
        try:
            process_sync_queue.apply_async(kwargs={"limit": limit, "backfill_limit": backfill_limit})
            return {"dispatched": True, "message": "Sync worker task queued"}
        except Exception as e:
            logger.warning("Celery unavailable, running inline: %s", e)
    processed = await process_pending_sync_events(db, limit=limit)
    enqueued = await backfill_unsynced_findings(db, limit=backfill_limit)
    return {
        "processed": processed,
        "backfill_enqueued": enqueued,
        "limit": limit,
        "backfill_limit": backfill_limit,
    }


@router.post("/poll-linear")
async def poll_linear_api(
    use_celery: bool = True,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Poll Linear API for [VAT] blocks in comments and descriptions.
    Use when webhooks aren't configured. Uses same credentials as Linear integration settings.
    No-op when VAT_LINEAR_POLL_ENABLED=false.
    - use_celery=true (default): dispatch to Celery worker (non-blocking)
    - use_celery=false: run inline (for debugging)
    """
    if use_celery:
        try:
            poll_linear.apply_async()
            return {"dispatched": True, "message": "Linear poll task queued"}
        except Exception as e:
            logger.warning("Celery unavailable, running inline: %s", e)
    result = await poll_linear_for_updates(db)
    return result


@router.post("/link-linear")
async def link_linear(
    max_issues: int = 500,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Pull existing Linear issues and link them to VAT findings by CVE ID.
    Use when your Aikido workspace already tracks issues in Linear — VAT will detect
    matching issues and mark findings as "already tracked" instead of creating duplicates.
    """
    result = await link_linear_issues_to_findings(db, max_issues=max_issues)
    return result


@router.post("/backfill")
async def trigger_backfill(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Enqueue create_issue for unsynced findings (Open/Reopened, no tracker_id).
    Use after bootstrap or when adding tracker config. Triggers Celery worker to process.
    """
    enqueued = await backfill_unsynced_findings(db, limit=limit)
    if enqueued > 0:
        trigger_sync_worker(countdown=1)
    return {"enqueued": enqueued, "limit": limit}


@router.post("/retry-failed")
async def retry_failed_linear(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Reset failed Linear sync events to pending so they retry.
    Use after fixing Linear config (e.g. wrong team ID). Triggers sync worker.
    """
    reset_count = await reset_failed_tracker_events(db, "linear")
    await db.commit()
    if reset_count > 0:
        trigger_sync_worker(countdown=2)
    return {"reset": reset_count, "message": f"Reset {reset_count} failed events for retry"}
