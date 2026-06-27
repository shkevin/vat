"""Scheduled maintenance tasks (Celery Beat)."""

from __future__ import annotations

import asyncio
import logging

from celery.schedules import crontab

from app.celery_app import app
from app.core.database import async_session
from app.services.decision_ledger import reconcile_decision_links
from app.services.waiver_expiry import enforce_waiver_expiry

logger = logging.getLogger(__name__)


@app.task(bind=True, name="app.tasks.maintenance_tasks.enforce_waiver_expiry")
def enforce_waiver_expiry_task(self) -> dict:
    """Daily waiver expiry: ledger-first, finding fallback."""
    try:
        count = asyncio.run(enforce_waiver_expiry())
        return {"reopened": count}
    except Exception as exc:
        logger.exception("Waiver expiry task failed: %s", exc)
        raise self.retry(exc=exc, countdown=300, max_retries=2) from exc


@app.task(bind=True, name="app.tasks.maintenance_tasks.reconcile_decisions")
def reconcile_decisions_task(self) -> dict:
    """Daily decision re-link reconciliation: repair drift between findings and ledger."""

    async def _run() -> dict:
        async with async_session() as db:
            return await reconcile_decision_links(db, cross_tenant=True, limit=20000)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.exception("Decision reconciliation task failed: %s", exc)
        raise self.retry(exc=exc, countdown=300, max_retries=2) from exc
