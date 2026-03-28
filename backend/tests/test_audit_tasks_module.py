"""Focused tests for app.tasks.audit_tasks module coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.tasks import audit_tasks


class _Engine:
    async def dispose(self):
        return None


class _Ctx:
    def __init__(self, db):
        self._db = db

    async def __aenter__(self):
        return self._db

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Factory:
    def __init__(self, db):
        self._db = db

    def __call__(self):
        return _Ctx(self._db)


@pytest.mark.asyncio
async def test_run_daily_checkpoint_disabled(monkeypatch):
    # Direct monkeypatch on function value to avoid config/environment coupling.
    monkeypatch.setattr(audit_tasks, "get_settings", lambda: SimpleNamespace(
        audit_daily_checkpoint_enabled=False,
        audit_checkpoint_retention_class="standard",
        database_url="sqlite+aiosqlite://",
    ))
    out = await audit_tasks._run_daily_checkpoint()
    assert out["skipped"] is True
    assert "audit_daily_checkpoint_enabled=false" in out["reason"]


@pytest.mark.asyncio
async def test_run_daily_checkpoint_success(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    cp = SimpleNamespace(
        checkpoint_date="2026-01-01",
        retention_class="standard",
        event_count=12,
        anchor_hash="abc123",
    )
    monkeypatch.setattr(
        audit_tasks,
        "get_settings",
        lambda: SimpleNamespace(
            audit_daily_checkpoint_enabled=True,
            audit_checkpoint_retention_class="standard",
            database_url="sqlite+aiosqlite://",
        ),
    )
    monkeypatch.setattr(audit_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(audit_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(audit_tasks, "create_daily_checkpoint", AsyncMock(return_value=cp))

    out = await audit_tasks._run_daily_checkpoint()
    assert out["checkpoint_date"] == "2026-01-01"
    assert out["retention_class"] == "standard"
    assert out["event_count"] == 12
    assert out["anchor_hash"] == "abc123"
    assert db.commit.await_count == 1


def test_run_daily_audit_checkpoint_task_wrapper(monkeypatch):
    monkeypatch.setattr(
        audit_tasks,
        "_run_daily_checkpoint",
        AsyncMock(return_value={"checkpoint_date": "2026-01-01"}),
    )
    assert audit_tasks.run_daily_audit_checkpoint.run() == {"checkpoint_date": "2026-01-01"}

    monkeypatch.setattr(
        audit_tasks,
        "_run_daily_checkpoint",
        AsyncMock(side_effect=Exception("boom")),
    )
    monkeypatch.setattr(
        audit_tasks.run_daily_audit_checkpoint,
        "retry",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("retry-called")),
    )
    with pytest.raises(RuntimeError, match="retry-called"):
        audit_tasks.run_daily_audit_checkpoint.run()
