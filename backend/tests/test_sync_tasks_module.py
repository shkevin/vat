"""Focused tests for app.tasks.sync_tasks module coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.tasks import sync_tasks


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
async def test_run_linear_poll_disabled_and_enabled_paths(monkeypatch):
    # Disabled path.
    monkeypatch.setattr(
        sync_tasks,
        "get_settings",
        lambda: SimpleNamespace(linear_poll_enabled=False, database_url="sqlite+aiosqlite://"),
    )
    out = await sync_tasks._run_linear_poll(force=False)
    assert out["issues_fetched"] == 0
    assert out["comments_processed"] == 0
    assert out["descriptions_processed"] == 0

    # Enabled/forced path.
    db = SimpleNamespace()
    monkeypatch.setattr(sync_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(sync_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(
        sync_tasks,
        "poll_linear_for_updates",
        AsyncMock(
            return_value={
                "issues_fetched": 2,
                "comments_processed": 3,
                "descriptions_processed": 1,
                "errors": [],
            }
        ),
    )
    out2 = await sync_tasks._run_linear_poll(force=True)
    assert out2["issues_fetched"] == 2
    assert out2["comments_processed"] == 3


@pytest.mark.asyncio
async def test_run_sync_batch(monkeypatch):
    db = SimpleNamespace()
    monkeypatch.setattr(
        sync_tasks,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite+aiosqlite://"),
    )
    monkeypatch.setattr(sync_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(sync_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(sync_tasks, "process_pending_sync_events", AsyncMock(return_value=7))
    assert await sync_tasks._run_sync_batch(limit=5) == 7


@pytest.mark.asyncio
async def test_run_sync_worker_tracker_not_configured(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    monkeypatch.setattr(
        sync_tasks,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite+aiosqlite://"),
    )
    monkeypatch.setattr(sync_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(sync_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(sync_tasks, "unlink_deleted_linear_issues", AsyncMock(return_value=0))
    monkeypatch.setattr(sync_tasks, "process_pending_sync_events", AsyncMock(return_value=4))
    monkeypatch.setattr(
        "app.services.credential_resolver.SettingsCredentialResolver",
        lambda: SimpleNamespace(
            get_tracker_credentials=AsyncMock(return_value={"api_key": "", "team_id": ""})
        ),
    )
    monkeypatch.setattr("app.api.settings.get_tracker_key", AsyncMock(return_value="linear"))
    monkeypatch.setattr("app.api.settings.get_tracker_push_mode", AsyncMock(return_value="groups"))

    out = await sync_tasks._run_sync_worker(
        limit=10,
        backfill_limit=5,
        corrections_limit=5,
        parallel_batches=1,
    )
    assert out["processed"] == 4
    assert out["backfill_enqueued"] == 0
    assert out["corrections_enqueued"] == 0
    assert out["linked"] == 0


@pytest.mark.asyncio
async def test_run_sync_worker_parallel_batches(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    monkeypatch.setattr(
        sync_tasks,
        "get_settings",
        lambda: SimpleNamespace(database_url="sqlite+aiosqlite://"),
    )
    monkeypatch.setattr(sync_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(sync_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(sync_tasks, "unlink_deleted_linear_issues", AsyncMock(return_value=1))
    monkeypatch.setattr(sync_tasks, "link_linear_issues_to_findings", AsyncMock(return_value={"linked": 2, "fetched": 3}))
    monkeypatch.setattr(sync_tasks, "backfill_tracker_corrections", AsyncMock(return_value=2))
    monkeypatch.setattr(sync_tasks, "backfill_unsynced_findings", AsyncMock(return_value=1))
    monkeypatch.setattr(sync_tasks, "_run_sync_batch", AsyncMock(side_effect=[2, 3]))
    monkeypatch.setattr(
        "app.services.credential_resolver.SettingsCredentialResolver",
        lambda: SimpleNamespace(
            get_tracker_credentials=AsyncMock(return_value={"api_key": "k", "team_id": "t"})
        ),
    )
    monkeypatch.setattr("app.api.settings.get_tracker_key", AsyncMock(return_value="linear"))
    monkeypatch.setattr("app.api.settings.get_tracker_push_mode", AsyncMock(return_value="groups"))

    out = await sync_tasks._run_sync_worker(
        limit=10,
        backfill_limit=5,
        corrections_limit=5,
        parallel_batches=2,
    )
    assert out["processed"] == 5
    assert out["linked"] == 2
    assert out["link_fetched"] == 3
    assert out["unlinked"] == 1


def test_task_wrappers_and_retry_paths(monkeypatch):
    # process_sync_queue success with default concurrency.
    monkeypatch.setattr(
        sync_tasks,
        "get_settings",
        lambda: SimpleNamespace(celery_worker_concurrency=3),
    )
    monkeypatch.setattr(
        sync_tasks,
        "_run_sync_worker",
        AsyncMock(return_value={"processed": 1}),
    )
    assert sync_tasks.process_sync_queue.run(limit=5, backfill_limit=2, corrections_limit=2) == {"processed": 1}

    # process_sync_queue retry on failure.
    monkeypatch.setattr(sync_tasks, "_run_sync_worker", AsyncMock(side_effect=Exception("boom")))
    monkeypatch.setattr(
        sync_tasks.process_sync_queue,
        "retry",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("retry-called")),
    )
    with pytest.raises(RuntimeError, match="retry-called"):
        sync_tasks.process_sync_queue.run()

    # poll_linear success and retry.
    monkeypatch.setattr(sync_tasks, "_run_linear_poll", AsyncMock(return_value={"issues_fetched": 0}))
    assert sync_tasks.poll_linear.run(force=True) == {"issues_fetched": 0}
    monkeypatch.setattr(sync_tasks, "_run_linear_poll", AsyncMock(side_effect=Exception("boom")))
    monkeypatch.setattr(
        sync_tasks.poll_linear,
        "retry",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("retry-called")),
    )
    with pytest.raises(RuntimeError, match="retry-called"):
        sync_tasks.poll_linear.run(force=False)

    # reconcile_linear success and retry.
    monkeypatch.setattr(sync_tasks, "_run_linear_poll", AsyncMock(return_value={"issues_fetched": 0}))
    assert sync_tasks.reconcile_linear.run() == {"issues_fetched": 0}
    monkeypatch.setattr(sync_tasks, "_run_linear_poll", AsyncMock(side_effect=Exception("boom")))
    monkeypatch.setattr(
        sync_tasks.reconcile_linear,
        "retry",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("retry-called")),
    )
    with pytest.raises(RuntimeError, match="retry-called"):
        sync_tasks.reconcile_linear.run()


def test_trigger_sync_worker(monkeypatch):
    called = {"n": 0}

    def _ok_apply_async(countdown=2):
        called["n"] += 1

    monkeypatch.setattr(sync_tasks.process_sync_queue, "apply_async", _ok_apply_async)
    sync_tasks.trigger_sync_worker(countdown=4)
    assert called["n"] == 1

    def _bad_apply_async(countdown=2):
        raise RuntimeError("no queue")

    monkeypatch.setattr(sync_tasks.process_sync_queue, "apply_async", _bad_apply_async)
    # Should not raise.
    sync_tasks.trigger_sync_worker(countdown=1)
