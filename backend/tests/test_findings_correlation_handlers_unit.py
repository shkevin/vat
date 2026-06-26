"""Direct unit tests for correlation handlers in findings API."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api import findings as findings_api
from app.schemas.auth import UserContext


def _ctx() -> UserContext:
    return UserContext(
        user_id="u-1",
        email="reviewer@vat.local",
        tenant_id="t-default",
        role="reviewer",
        raw_identity="reviewer@vat.local",
    )


def _edge(active: bool = True, operation_id: str = "op-1"):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id="edge-1",
        finding_id_a="f-1",
        finding_id_b="f-2",
        edge_type="same_control",
        confidence="medium",
        evidence={"e": 1},
        active=active,
        operation_id=operation_id,
        created_by="system",
        created_at=now,
        updated_at=now,
        removed_by=None if active else "reviewer@vat.local",
        removed_at=None if active else now,
        remove_reason=None if active else "manual",
    )


@pytest.mark.asyncio
async def test_get_finding_correlations_handler_success(monkeypatch):
    db = AsyncMock()
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(return_value=SimpleNamespace(tenant_id=None)),
    )
    monkeypatch.setattr(
        findings_api,
        "list_active_edges_for_finding",
        AsyncMock(return_value=[_edge(active=True)]),
    )

    out = await findings_api.get_finding_correlations("f-1", db=db, ctx=_ctx())
    assert out["count"] == 1
    assert out["edges"][0]["peer_finding_id"] == "f-2"


@pytest.mark.asyncio
async def test_remove_and_restore_handlers_success(monkeypatch):
    db = AsyncMock()
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id=None), SimpleNamespace(tenant_id=None)]),
    )
    monkeypatch.setattr(
        findings_api,
        "deactivate_edge",
        AsyncMock(return_value=_edge(active=False, operation_id="op-deact")),
    )
    removed = await findings_api.remove_finding_correlation(
        "f-1",
        "f-2",
        body=findings_api.CorrelationEdgeActionRequest(reason="manual split"),
        db=db,
        ctx=_ctx(),
    )
    assert removed["deactivated"] is True
    assert removed["operation_id"] == "op-deact"
    db.commit.assert_awaited()

    db.commit.reset_mock()
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id=None), SimpleNamespace(tenant_id=None)]),
    )
    monkeypatch.setattr(
        findings_api,
        "reactivate_edge",
        AsyncMock(return_value=_edge(active=True, operation_id="op-react")),
    )
    restored = await findings_api.restore_finding_correlation(
        "f-1",
        "f-2",
        body=findings_api.CorrelationEdgeActionRequest(reason="confirm same control"),
        db=db,
        ctx=_ctx(),
    )
    assert restored["restored"] is True
    assert restored["operation_id"] == "op-react"
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_remove_and_restore_handlers_not_found(monkeypatch):
    db = AsyncMock()
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc:
        await findings_api.remove_finding_correlation(
            "missing",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="n/a"),
            db=db,
            ctx=_ctx(),
        )
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id=None), SimpleNamespace(tenant_id=None)]),
    )
    monkeypatch.setattr(findings_api, "reactivate_edge", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc2:
        await findings_api.restore_finding_correlation(
            "f-1",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="n/a"),
            db=db,
            ctx=_ctx(),
        )
    assert exc2.value.status_code == 404


@pytest.mark.asyncio
async def test_history_and_operation_lookup_handlers(monkeypatch):
    db = AsyncMock()
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(return_value=SimpleNamespace(tenant_id=None)),
    )
    monkeypatch.setattr(
        findings_api,
        "list_edges_for_finding",
        AsyncMock(return_value=[_edge(active=False, operation_id="op-hist")]),
    )
    out = await findings_api.get_finding_correlation_history("f-1", db=db, ctx=_ctx())
    assert out["count"] == 1
    assert out["edges"][0]["active"] is False

    monkeypatch.setattr(
        findings_api,
        "list_edges_by_operation_id",
        AsyncMock(return_value=[_edge(active=True, operation_id="op-lookup")]),
    )
    # two get_finding calls for a/b membership check
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id=None), SimpleNamespace(tenant_id=None)]),
    )
    op_out = await findings_api.get_correlation_operation_history(
        "op-lookup", db=db, ctx=_ctx()
    )
    assert op_out["count"] == 1
    assert op_out["edges"][0]["operation_id"] == "op-lookup"


@pytest.mark.asyncio
async def test_correlation_handler_tenant_and_not_found_branches(monkeypatch):
    db = AsyncMock()

    # get_finding_correlations: missing finding + tenant mismatch
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc:
        await findings_api.get_finding_correlations("f-1", db=db, ctx=_ctx())
    assert exc.value.status_code == 404

    mismatch_ctx = UserContext(
        user_id="u-1",
        email="reviewer@vat.local",
        tenant_id="tenant-a",
        role="reviewer",
        raw_identity="reviewer@vat.local",
    )
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(return_value=SimpleNamespace(tenant_id="tenant-b")),
    )
    with pytest.raises(HTTPException) as exc:
        await findings_api.get_finding_correlations("f-1", db=db, ctx=mismatch_ctx)
    assert exc.value.status_code == 404

    # remove: tenant mismatch + missing edge
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id="tenant-a"), SimpleNamespace(tenant_id="tenant-b")]),
    )
    with pytest.raises(HTTPException) as exc:
        await findings_api.remove_finding_correlation(
            "f-1",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="x"),
            db=db,
            ctx=mismatch_ctx,
        )
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id=None), SimpleNamespace(tenant_id=None)]),
    )
    monkeypatch.setattr(findings_api, "deactivate_edge", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc:
        await findings_api.remove_finding_correlation(
            "f-1",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="x"),
            db=db,
            ctx=_ctx(),
        )
    assert exc.value.status_code == 404

    # restore: missing finding + tenant mismatch
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc:
        await findings_api.restore_finding_correlation(
            "f-1",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="x"),
            db=db,
            ctx=_ctx(),
        )
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id="tenant-a"), SimpleNamespace(tenant_id="tenant-b")]),
    )
    with pytest.raises(HTTPException) as exc:
        await findings_api.restore_finding_correlation(
            "f-1",
            "f-2",
            body=findings_api.CorrelationEdgeActionRequest(reason="x"),
            db=db,
            ctx=mismatch_ctx,
        )
    assert exc.value.status_code == 404

    # history: missing finding + tenant mismatch
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as exc:
        await findings_api.get_finding_correlation_history("f-1", db=db, ctx=_ctx())
    assert exc.value.status_code == 404

    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(return_value=SimpleNamespace(tenant_id="tenant-b")),
    )
    with pytest.raises(HTTPException) as exc:
        await findings_api.get_finding_correlation_history("f-1", db=db, ctx=mismatch_ctx)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_operation_lookup_empty_and_tenant_filter_continue(monkeypatch):
    db = AsyncMock()
    # empty branch
    monkeypatch.setattr(findings_api, "list_edges_by_operation_id", AsyncMock(return_value=[]))
    empty = await findings_api.get_correlation_operation_history("op-none", db=db, ctx=_ctx())
    assert empty["count"] == 0

    # tenant filter branch with continue
    mismatch_ctx = UserContext(
        user_id="u-1",
        email="reviewer@vat.local",
        tenant_id="tenant-a",
        role="reviewer",
        raw_identity="reviewer@vat.local",
    )
    monkeypatch.setattr(
        findings_api,
        "list_edges_by_operation_id",
        AsyncMock(return_value=[_edge(active=True, operation_id="op-x")]),
    )
    monkeypatch.setattr(
        findings_api,
        "get_finding",
        AsyncMock(side_effect=[SimpleNamespace(tenant_id="tenant-b"), SimpleNamespace(tenant_id="tenant-b")]),
    )
    filtered = await findings_api.get_correlation_operation_history(
        "op-x", db=db, ctx=mismatch_ctx
    )
    assert filtered["count"] == 0


@pytest.mark.asyncio
async def test_crosswalk_run_handlers(monkeypatch):
    db = AsyncMock()

    run = SimpleNamespace(
        id="run-1",
        source="unit",
        source_version="v1",
        status="completed",
        stats={"inserted": 1, "updated": 0, "rejected": 0},
    )
    monkeypatch.setattr(
        findings_api,
        "ingest_crosswalk_entries",
        AsyncMock(return_value=run),
    )
    admin_ctx = UserContext(
        user_id="admin",
        email="admin@vat.local",
        tenant_id=None,
        role="admin",
        raw_identity="admin@vat.local",
    )
    run_out = await findings_api.post_crosswalk_run(
        body=findings_api.CrosswalkRunRequest(
            source="unit",
            source_version="v1",
            entries=[
                findings_api.CrosswalkEntryRequest(
                    from_namespace="rule_id",
                    from_value="SV-1",
                    to_namespace="stable_rule_key",
                    to_value="V-1",
                )
            ],
        ),
        db=db,
        ctx=admin_ctx,
    )
    assert run_out["run_id"] == "run-1"
    db.commit.assert_awaited()

