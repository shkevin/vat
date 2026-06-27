"""Scheduled maintenance tasks (Celery Beat)."""

from __future__ import annotations

import asyncio
import logging

from celery.schedules import crontab

from app.celery_app import app
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
