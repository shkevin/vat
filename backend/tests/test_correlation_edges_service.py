"""Unit tests for correlation edge helpers."""

import pytest
from unittest.mock import AsyncMock, Mock

from app.models.correlation_edge import CorrelationEdge
from app.services.correlation_edges import (
    _edge_id,
    deactivate_edge,
    list_active_edges_for_finding,
    list_edges_by_operation_id,
    list_edges_for_finding,
    normalize_pair,
    reactivate_edge,
)


def test_normalize_pair_is_undirected():
    assert normalize_pair("f-2", "f-1") == ("f-1", "f-2")
    assert normalize_pair("f-1", "f-2") == ("f-1", "f-2")


def test_normalize_pair_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        normalize_pair("", "f-2")
    with pytest.raises(ValueError):
        normalize_pair("f-1", "f-1")


def test_edge_id_is_stable_for_pair():
    a, b = normalize_pair("f-b", "f-a")
    assert _edge_id(a, b) == _edge_id(*normalize_pair("f-a", "f-b"))


@pytest.mark.asyncio
async def test_deactivate_and_reactivate_edge_with_mock_session():
    db = AsyncMock()
    row = CorrelationEdge(
        id=_edge_id("f-1", "f-2"),
        finding_id_a="f-1",
        finding_id_b="f-2",
        edge_type="same_control",
        confidence="medium",
        evidence={},
        active=True,
        operation_id="op-1",
    )
    db.get.return_value = row

    deactivated = await deactivate_edge(
        db,
        finding_id_left="f-1",
        finding_id_right="f-2",
        removed_by="reviewer@example.com",
        remove_reason="manual review",
    )
    assert deactivated is row
    assert row.active is False
    assert row.removed_by == "reviewer@example.com"
    assert row.remove_reason == "manual review"
    assert row.operation_id

    reactivated = await reactivate_edge(
        db,
        finding_id_left="f-2",
        finding_id_right="f-1",
        reactivated_by="reviewer@example.com",
    )
    assert reactivated is row
    assert row.active is True
    assert row.removed_by is None
    assert row.remove_reason is None
    assert row.operation_id


@pytest.mark.asyncio
async def test_deactivate_and_reactivate_edge_not_found():
    db = AsyncMock()
    db.get.return_value = None
    assert (
        await deactivate_edge(
            db,
            finding_id_left="f-1",
            finding_id_right="f-2",
            removed_by="reviewer@example.com",
            remove_reason="none",
        )
        is None
    )
    assert (
        await reactivate_edge(
            db,
            finding_id_left="f-1",
            finding_id_right="f-2",
            reactivated_by="reviewer@example.com",
        )
        is None
    )


@pytest.mark.asyncio
async def test_list_edge_helpers_with_mock_execute_result():
    db = AsyncMock()
    rows = [
        CorrelationEdge(
            id=_edge_id("f-1", "f-2"),
            finding_id_a="f-1",
            finding_id_b="f-2",
            edge_type="same_control",
            confidence="medium",
            evidence={},
            active=True,
            operation_id="op-abc",
        )
    ]

    execute_result = Mock()
    scalars_result = Mock()
    scalars_result.all.return_value = rows
    execute_result.scalars.return_value = scalars_result
    db.execute.return_value = execute_result

    active = await list_active_edges_for_finding(db, "f-1")
    full = await list_edges_for_finding(db, "f-1", include_inactive=True)
    by_op = await list_edges_by_operation_id(db, "op-abc")

    assert active == rows
    assert full == rows
    assert by_op == rows


@pytest.mark.asyncio
async def test_list_edge_helpers_empty_inputs():
    db = AsyncMock()
    assert await list_active_edges_for_finding(db, "") == []
    assert await list_edges_for_finding(db, "", include_inactive=True) == []
    assert await list_edges_by_operation_id(db, "") == []

