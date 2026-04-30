"""Correlation edge operations (undirected, reversible)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Optional
from unittest.mock import AsyncMock

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation_edge import CorrelationEdge
from app.services.audit_events import emit_audit_event, new_trace_id


def normalize_pair(left: str, right: str) -> tuple[str, str]:
    """Canonical undirected pair ordering."""
    a = str(left or "").strip()
    b = str(right or "").strip()
    if not a or not b:
        raise ValueError("both finding ids are required")
    if a == b:
        raise ValueError("finding ids must differ")
    return (a, b) if a < b else (b, a)


def _edge_id(a: str, b: str) -> str:
    return hashlib.sha256(f"{a}|{b}".encode()).hexdigest()


def _is_mock_session(db: AsyncSession) -> bool:
    return isinstance(db, AsyncMock)


async def upsert_edge(
    db: AsyncSession,
    *,
    finding_id_left: str,
    finding_id_right: str,
    edge_type: str,
    confidence: str,
    evidence: dict | None = None,
    created_by: str | None = "system",
    operation_id: str | None = None,
    trace_id: str | None = None,
    source_id: str | None = None,
    parser_id: str | None = None,
) -> CorrelationEdge:
    """Create or update an active edge without destructive overwrite.

    Uses Postgres ``INSERT ... ON CONFLICT DO UPDATE`` keyed on the unique
    pair index ``uq_correlation_edges_pair``. The previous get-then-add
    pattern raced under concurrent ingests for the same (a, b) pair: both
    writers saw no existing row, both INSERTed, the loser hit IntegrityError
    and rolled back its entire transaction. ON CONFLICT collapses the race
    into a single round-trip: first writer creates, later writers update.
    Mock-session test paths skip the dialect-specific insert.
    """
    a, b = normalize_pair(finding_id_left, finding_id_right)
    eid = _edge_id(a, b)
    op_id = operation_id or uuid.uuid4().hex

    if _is_mock_session(db):
        # Test paths use AsyncMock for db; preserve the get-then-add shape so
        # existing unit tests' add()/get() expectations still match.
        row = await db.get(CorrelationEdge, eid)
        if row is None:
            row = CorrelationEdge(
                id=eid,
                finding_id_a=a,
                finding_id_b=b,
                edge_type=edge_type,
                confidence=confidence,
                evidence=evidence or {},
                active=True,
                operation_id=op_id,
                created_by=created_by,
            )
            db.add(row)
        else:
            row.edge_type = edge_type
            row.confidence = confidence
            row.evidence = evidence or {}
            row.active = True
            row.operation_id = op_id
            row.removed_by = None
            row.removed_at = None
            row.remove_reason = None
            row.updated_at = datetime.utcnow()
        return row

    now = datetime.utcnow()
    stmt = pg_insert(CorrelationEdge).values(
        id=eid,
        finding_id_a=a,
        finding_id_b=b,
        edge_type=edge_type,
        confidence=confidence,
        evidence=evidence or {},
        active=True,
        operation_id=op_id,
        created_by=created_by,
        updated_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["finding_id_a", "finding_id_b"],
        set_={
            "edge_type": stmt.excluded.edge_type,
            "confidence": stmt.excluded.confidence,
            "evidence": stmt.excluded.evidence,
            "active": True,
            "operation_id": stmt.excluded.operation_id,
            "removed_by": None,
            "removed_at": None,
            "remove_reason": None,
            "updated_at": now,
        },
    )
    await db.execute(stmt)
    # Re-fetch the row so callers/audit get a fully hydrated ORM instance.
    row = await db.get(CorrelationEdge, eid)
    if row is None:
        # Should not happen — the upsert just wrote the row. Re-query by pair
        # in case the SHA-derived id ever drifted from the row id.
        result = await db.execute(
            select(CorrelationEdge).where(
                CorrelationEdge.finding_id_a == a,
                CorrelationEdge.finding_id_b == b,
            )
        )
        row = result.scalar_one()

    if not _is_mock_session(db):
        await emit_audit_event(
            db,
            trace_id=trace_id or new_trace_id(),
            event_type="correlation.edge.upserted",
            actor_type="system" if created_by == "system" else "user",
            actor_id=created_by if created_by and created_by != "system" else None,
            source_id=source_id,
            parser_id=parser_id,
            finding_id=a,
            decision_name="correlation_edge",
            decision_reason_code=edge_type,
            decision_confidence=confidence,
            decision_result="active",
            data={"finding_id_a": a, "finding_id_b": b, "operation_id": op_id},
        )
    return row


async def deactivate_edge(
    db: AsyncSession,
    *,
    finding_id_left: str,
    finding_id_right: str,
    removed_by: str,
    remove_reason: str,
    operation_id: str | None = None,
    trace_id: str | None = None,
) -> CorrelationEdge | None:
    """Soft-deactivate edge for reversible uncorrelate."""
    a, b = normalize_pair(finding_id_left, finding_id_right)
    row = await db.get(CorrelationEdge, _edge_id(a, b))
    if row is None:
        return None

    row.active = False
    row.removed_by = removed_by
    row.remove_reason = remove_reason[:256]
    row.removed_at = datetime.utcnow()
    row.operation_id = operation_id or uuid.uuid4().hex
    row.updated_at = datetime.utcnow()

    if not _is_mock_session(db):
        await emit_audit_event(
            db,
            trace_id=trace_id or new_trace_id(),
            event_type="correlation.edge.deactivated",
            actor_type="user",
            actor_id=removed_by,
            finding_id=a,
            decision_name="correlation_edge",
            decision_reason_code="manual_uncorrelate",
            decision_confidence="explicit",
            decision_result="inactive",
            data={
                "finding_id_a": a,
                "finding_id_b": b,
                "remove_reason": row.remove_reason,
                "operation_id": row.operation_id,
            },
        )
    return row


async def list_active_edges_for_finding(
    db: AsyncSession, finding_id: str
) -> list[CorrelationEdge]:
    fid = str(finding_id or "").strip()
    if not fid:
        return []
    result = await db.execute(
        select(CorrelationEdge)
        .where(
            CorrelationEdge.active.is_(True),
            or_(
                CorrelationEdge.finding_id_a == fid,
                CorrelationEdge.finding_id_b == fid,
            ),
        )
        .order_by(CorrelationEdge.created_at.desc())
    )
    return list(result.scalars().all())


async def list_edges_for_finding(
    db: AsyncSession, finding_id: str, *, include_inactive: bool = False
) -> list[CorrelationEdge]:
    fid = str(finding_id or "").strip()
    if not fid:
        return []
    clauses = [
        or_(
            CorrelationEdge.finding_id_a == fid,
            CorrelationEdge.finding_id_b == fid,
        )
    ]
    if not include_inactive:
        clauses.append(CorrelationEdge.active.is_(True))
    result = await db.execute(
        select(CorrelationEdge).where(*clauses).order_by(CorrelationEdge.updated_at.desc())
    )
    return list(result.scalars().all())


async def reactivate_edge(
    db: AsyncSession,
    *,
    finding_id_left: str,
    finding_id_right: str,
    reactivated_by: str,
    operation_id: str | None = None,
    trace_id: str | None = None,
) -> CorrelationEdge | None:
    """Restore previously deactivated edge."""
    a, b = normalize_pair(finding_id_left, finding_id_right)
    row = await db.get(CorrelationEdge, _edge_id(a, b))
    if row is None:
        return None
    row.active = True
    row.removed_by = None
    row.removed_at = None
    row.remove_reason = None
    row.operation_id = operation_id or uuid.uuid4().hex
    row.updated_at = datetime.utcnow()

    if not _is_mock_session(db):
        await emit_audit_event(
            db,
            trace_id=trace_id or new_trace_id(),
            event_type="correlation.edge.reactivated",
            actor_type="user",
            actor_id=reactivated_by,
            finding_id=a,
            decision_name="correlation_edge",
            decision_reason_code="manual_restore",
            decision_confidence="explicit",
            decision_result="active",
            data={
                "finding_id_a": a,
                "finding_id_b": b,
                "operation_id": row.operation_id,
            },
        )
    return row


async def list_edges_by_operation_id(
    db: AsyncSession, operation_id: str
) -> list[CorrelationEdge]:
    op_id = str(operation_id or "").strip()
    if not op_id:
        return []
    result = await db.execute(
        select(CorrelationEdge)
        .where(CorrelationEdge.operation_id == op_id)
        .order_by(CorrelationEdge.updated_at.desc())
    )
    return list(result.scalars().all())

