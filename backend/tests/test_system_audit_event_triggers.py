"""System audit trigger coverage for seed/export entrypoints."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api import audit as audit_api
from app.api import export as export_api
from app.api import seed as seed_api


@pytest.mark.asyncio
async def test_seed_all_emits_system_audit_event(monkeypatch):
    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr(seed_api, "create_findings_bulk", AsyncMock(return_value=3))
    emit_spy = AsyncMock(return_value="evt-seed")
    monkeypatch.setattr(seed_api, "emit_audit_event", emit_spy)
    monkeypatch.setattr(seed_api, "new_trace_id", lambda: "trace-seed")

    body = seed_api.SeedRequest(findings=[{"id": "f1"}], sbom=[], tenants=[], users=[])
    ctx = SimpleNamespace(email="admin@example.com", user_id="u-1")
    result = await seed_api.seed_all(body=body, db=db, _ctx=ctx)

    assert result["findings"] == 3
    assert emit_spy.await_count == 1
    assert db.commit.await_count == 1
    kwargs = emit_spy.await_args.kwargs
    assert kwargs["event_type"] == "seed.dataset.loaded"
    assert kwargs["actor_id"] == "admin@example.com"
    assert kwargs["decision_result"] == "loaded"


@pytest.mark.asyncio
async def test_export_bundle_emits_system_audit_event(monkeypatch):
    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr(export_api, "build_export_bundle", AsyncMock(return_value=b"zip-bytes"))
    emit_spy = AsyncMock(return_value="evt-export")
    monkeypatch.setattr(export_api, "emit_audit_event", emit_spy)
    monkeypatch.setattr(export_api, "new_trace_id", lambda: "trace-export")

    ctx = SimpleNamespace(email="admin@example.com", user_id="u-1", tenant_id="t-1")
    resp = await export_api.get_export_bundle(db=db, ctx=ctx)

    assert resp.status_code == 200
    assert emit_spy.await_count == 1
    assert db.commit.await_count == 1
    kwargs = emit_spy.await_args.kwargs
    assert kwargs["event_type"] == "export.bundle.generated"
    assert kwargs["actor_id"] == "admin@example.com"
    assert kwargs["decision_result"] == "generated"
    assert kwargs["data"]["includeAuditEvents"] is True


class _ExecuteResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


@pytest.mark.asyncio
async def test_audit_export_emits_event_even_when_zero_rows(monkeypatch):
    db = MagicMock()
    db.execute = AsyncMock(return_value=_ExecuteResult([]))
    db.commit = AsyncMock()
    emit_spy = AsyncMock(return_value="evt-audit-export")
    monkeypatch.setattr(audit_api, "emit_audit_event", emit_spy)
    monkeypatch.setattr(audit_api, "new_trace_id", lambda: "trace-audit-export")

    ctx = SimpleNamespace(email="admin@example.com", user_id="u-1")
    resp = await audit_api.export_audit_events(db=db, _ctx=ctx)

    assert resp.status_code == 200
    assert emit_spy.await_count == 1
    kwargs = emit_spy.await_args.kwargs
    assert kwargs["event_type"] == "export.audit_bundle.generated"
    assert kwargs["trace_id"] == "trace-audit-export"
    assert kwargs["data"]["count"] == 0
    assert db.commit.await_count == 1

