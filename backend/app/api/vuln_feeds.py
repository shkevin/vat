"""Vulnerability feed status and refresh APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.services.vuln_feeds import (
    get_feed_runs,
    get_feed_records,
    get_feed_summary,
    match_sbom_with_osv,
    mark_vuln_feed_refresh_finished,
    mark_vuln_feed_refresh_running,
    refresh_enabled_feeds,
    release_vuln_feed_refresh_lock,
    request_vuln_feed_refresh_enqueue,
    top_vulnerabilities,
    try_acquire_vuln_feed_refresh_lock,
)
from app.tasks.vuln_feed_tasks import run_vuln_feed_refresh

router = APIRouter()


@router.get("/summary")
async def feed_summary(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(get_current_user_context),
):
    summary = await get_feed_summary(db)
    top_vulns = await top_vulnerabilities(db, limit=20)
    return {**summary, "top_vulnerabilities": top_vulns}


@router.get("/runs")
async def feed_runs(
    source: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(get_current_user_context),
):
    runs = await get_feed_runs(db, source=source, limit=limit)
    return {"count": len(runs), "runs": runs}


@router.get("/records")
async def feed_records(
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(get_current_user_context),
):
    return await get_feed_records(
        db,
        source=source,
        severity=severity,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.post("/refresh")
async def refresh_feeds(
    use_celery: bool = True,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    actor_id = ctx.email or ctx.user_id
    if use_celery:
        accepted, status = await request_vuln_feed_refresh_enqueue(db, actor_id=actor_id)
        if not accepted:
            return {
                "dispatched": False,
                "already_running": True,
                "status": status,
                "message": "Vulnerability feed refresh is already queued or running",
            }
        await db.commit()
        try:
            run_vuln_feed_refresh.apply_async(
                expires=max(60, get_settings().vuln_feed_task_expires_seconds)
            )
        except Exception as exc:
            await mark_vuln_feed_refresh_finished(
                db,
                status="failed",
                actor_id=actor_id,
                message=str(exc)[:500],
            )
            await db.commit()
            raise
        return {
            "dispatched": True,
            "already_running": False,
            "status": status,
            "message": "Vulnerability feed refresh task queued",
        }

    acquired = await try_acquire_vuln_feed_refresh_lock(db)
    if not acquired:
        return {
            "dispatched": False,
            "already_running": True,
            "message": "Vulnerability feed refresh is already running",
        }
    try:
        await mark_vuln_feed_refresh_running(db, actor_id=actor_id)
        try:
            result = await refresh_enabled_feeds(db, actor_id=actor_id)
            await mark_vuln_feed_refresh_finished(
                db,
                status="completed",
                actor_id=actor_id,
                message="Vulnerability feed refresh completed.",
            )
            await db.commit()
            return {"dispatched": False, "already_running": False, **result}
        except Exception as exc:
            await db.rollback()
            await mark_vuln_feed_refresh_finished(
                db,
                status="failed",
                actor_id=actor_id,
                message=str(exc)[:500],
            )
            await db.commit()
            raise
    finally:
        await release_vuln_feed_refresh_lock(db)


@router.post("/sbom-match")
async def sbom_match(
    package_limit: int = Query(default=250, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(get_current_user_context),
):
    result = await match_sbom_with_osv(db, package_limit=package_limit)
    return result
