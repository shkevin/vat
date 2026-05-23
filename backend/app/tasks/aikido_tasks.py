"""Celery tasks for durable Aikido full sync jobs."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.settings import get_aikido_credentials
from app.celery_app import app
from app.core.config import get_settings
from app.services.aikido_full_sync import run_full_sync
from app.services.aikido_sync_status import (
    build_progress_aikido_sync_status,
    build_terminal_aikido_sync_status,
    persist_aikido_sync_status,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

SYNC_RUNNING_MESSAGE = (
    "Sync running in background. This may take a few minutes. Refresh the page "
    "or check the Report tab when complete."
)


async def _run_aikido_full_sync(source_id: str) -> dict:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as db:
            creds = await get_aikido_credentials(db, source_id)
        started_at: str | None = None

        async def _on_progress(step: int, total: int, label: str) -> None:
            nonlocal started_at
            if not started_at:
                started_at = utc_now_iso()
            await persist_aikido_sync_status(
                source_id,
                build_progress_aikido_sync_status(
                    source_id,
                    message=SYNC_RUNNING_MESSAGE,
                    started_at=started_at,
                    step=step,
                    total=total,
                    label=label,
                ),
            )

        result = await run_full_sync(creds, source_id=source_id, on_progress=_on_progress)
        pull_err = result.get("pull", {}).get("error")
        dash_err = result.get("dashboard", {}).get("error")
        if pull_err or dash_err:
            message = str(pull_err or dash_err or "Sync failed")[:500]
            await persist_aikido_sync_status(
                source_id,
                build_terminal_aikido_sync_status(
                    source_id,
                    status="error",
                    message=message,
                    started_at=started_at,
                ),
            )
            return {"status": "error", "message": message, "result": result}

        message = "Sync complete. Refresh the Report tab to see updated data."
        await persist_aikido_sync_status(
            source_id,
            build_terminal_aikido_sync_status(
                source_id,
                status="success",
                message=message,
                started_at=started_at,
            ),
        )
        return {"status": "success", "message": message, "result": result}
    finally:
        await engine.dispose()


@app.task(bind=True, name="app.tasks.aikido_tasks.run_aikido_full_sync")
def run_aikido_full_sync(self, source_id: str) -> dict:
    try:
        return asyncio.run(_run_aikido_full_sync(source_id))
    except Exception as exc:
        logger.exception("Aikido full sync failed: %s", exc)
        try:
            asyncio.run(
                persist_aikido_sync_status(
                    source_id,
                    build_terminal_aikido_sync_status(
                        source_id,
                        status="error",
                        message=str(exc)[:500],
                        started_at=None,
                    ),
                )
            )
        except Exception:
            logger.exception("Failed to persist Aikido sync error status")
        raise self.retry(exc=exc, countdown=300, max_retries=1)


def trigger_aikido_full_sync(source_id: str, countdown: int = 0) -> None:
    run_aikido_full_sync.apply_async(
        args=[source_id],
        queue="vat-sync",
        countdown=countdown,
    )
