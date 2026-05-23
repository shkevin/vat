"""Durable status helpers for Aikido full sync jobs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.settings_model import SettingsKV

AIKIDO_FULL_SYNC_TOTAL_STEPS = 18
AIKIDO_SYNC_STATUS_PREFIX = "aikido_sync_status:"
AIKIDO_DASHBOARD_KEY = "aikido_dashboard_data"
AIKIDO_DASHBOARD_PREFIX = "aikido_dashboard_data:"


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def aikido_sync_status_key(source_id: str | None) -> str:
    sid = source_id if source_id else "default"
    return f"{AIKIDO_SYNC_STATUS_PREFIX}{sid}"


def aikido_dashboard_key(source_id: str | None) -> str:
    return (
        f"{AIKIDO_DASHBOARD_PREFIX}{source_id}" if source_id else AIKIDO_DASHBOARD_KEY
    )


def _snapshot(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status.get("status", "idle"),
        "message": status.get("message"),
        "started_at": status.get("started_at"),
        "step": int(status.get("step", 0) or 0),
        "total": int(status.get("total", 0) or 0),
        "label": status.get("label"),
        "source_id": status.get("source_id"),
    }


def build_running_aikido_sync_status(
    source_id: str | None,
    *,
    message: str,
    started_at: str | None = None,
) -> dict[str, Any]:
    return {
        "status": "running",
        "message": message,
        "started_at": started_at or utc_now_iso(),
        "step": 0,
        "total": AIKIDO_FULL_SYNC_TOTAL_STEPS,
        "label": "Queued",
        "source_id": source_id,
    }


def build_progress_aikido_sync_status(
    source_id: str | None,
    *,
    message: str,
    started_at: str | None,
    step: int,
    total: int,
    label: str,
) -> dict[str, Any]:
    return {
        "status": "running",
        "message": message,
        "started_at": started_at or utc_now_iso(),
        "step": step,
        "total": total,
        "label": label,
        "source_id": source_id,
    }


def build_terminal_aikido_sync_status(
    source_id: str | None,
    *,
    status: str,
    message: str,
    started_at: str | None,
    step: int = AIKIDO_FULL_SYNC_TOTAL_STEPS,
    total: int = AIKIDO_FULL_SYNC_TOTAL_STEPS,
    label: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "started_at": started_at,
        "step": step,
        "total": total,
        "label": label,
        "source_id": source_id,
    }


def coerce_stale_running_status(
    status: dict[str, Any],
    *,
    updated_at: datetime | None,
    stale_after_seconds: int,
) -> dict[str, Any]:
    current = _snapshot(status)
    if current.get("status") != "running" or not updated_at or stale_after_seconds <= 0:
        return current
    updated = updated_at
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - updated.astimezone(timezone.utc)
    if age.total_seconds() <= stale_after_seconds:
        return current
    current["status"] = "error"
    current["message"] = (
        "Aikido sync stalled before completion. The worker may have restarted; "
        "start a new sync to resume."
    )
    return current


async def upsert_aikido_sync_status(
    db: AsyncSession,
    source_id: str | None,
    status: dict[str, Any],
) -> None:
    key = aikido_sync_status_key(source_id)
    snapshot = _snapshot(status)
    row = (
        await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    ).scalar_one_or_none()
    if row:
        row.value = snapshot
        row.updated_at = utc_now_naive()
    else:
        db.add(SettingsKV(key=key, value=snapshot, updated_at=utc_now_naive()))


async def persist_aikido_sync_status(
    source_id: str | None,
    status: dict[str, Any],
) -> None:
    async with async_session() as session:
        await upsert_aikido_sync_status(session, source_id, status)
        await session.commit()


async def read_aikido_sync_status_record(
    db: AsyncSession,
    source_id: str | None,
) -> tuple[dict[str, Any] | None, datetime | None]:
    row = (
        await db.execute(
            select(SettingsKV).where(
                SettingsKV.key == aikido_sync_status_key(source_id)
            )
        )
    ).scalar_one_or_none()
    if not row or not isinstance(row.value, dict):
        return None, None
    return _snapshot(row.value), row.updated_at


async def read_aikido_last_synced_at(
    db: AsyncSession,
    source_id: str | None,
) -> str | None:
    expr = SettingsKV.value["fetchedAt"].as_string()
    value = (
        await db.execute(
            select(expr).where(SettingsKV.key == aikido_dashboard_key(source_id))
        )
    ).scalar_one_or_none()
    return value if isinstance(value, str) and value else None
