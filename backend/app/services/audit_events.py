"""Audit event emission and query helpers."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from contextvars import ContextVar
import json
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_event import AuditEvent
from app.models.audit_ledger_checkpoint import AuditLedgerCheckpoint
from app.services.otel import mirror_audit_event_to_otel
from app.services.observability import METRICS

import logging

logger = logging.getLogger("uvicorn.error")


def new_trace_id() -> str:
    """Create a lightweight trace identifier."""
    return uuid.uuid4().hex


def _stable_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


_bulk_audit_chain: ContextVar[Optional[dict[str, Optional[str]]]] = ContextVar(
    "vat_bulk_audit_chain", default=None
)
# Rows queued for one executemany instead of an INSERT per event. Autoflush fires
# between events (the ingest path runs many SELECTs), so db.add() alone still
# produced one INSERT statement each — 3.08 per finding.
_bulk_audit_rows: ContextVar[Optional[list[dict[str, Any]]]] = ContextVar(
    "vat_bulk_audit_rows", default=None
)


async def flush_bulk_audit_events(db) -> int:
    """Insert everything queued by bulk_audit_chain. Call before each commit."""
    rows = _bulk_audit_rows.get()
    if not rows:
        return 0
    # Core table insert, not insert(AuditEvent): the ORM-aware path runs
    # insertmanyvalues and split 488 rows into 424 single statements plus 26
    # batches. Every row carries created_at explicitly so there is no per-row
    # Python default left to compute and the parameter sets stay homogeneous.
    await db.execute(AuditEvent.__table__.insert(), rows)
    n = len(rows)
    rows.clear()
    return n


@asynccontextmanager
async def bulk_audit_chain():
    """Batch-friendly audit emission for a bulk replay (e.g. Aikido bootstrap).

    Inside this scope emit_audit_event keeps each trace's latest record_hash in
    memory instead of re-reading it, and stops flushing after every insert.

    Both matter: profiling the bootstrap showed 3.25 prev-hash SELECTs and 3.25
    audit INSERTs per finding — 31% of all SQL time — because the same trace_id
    was looked up repeatedly and the per-event flush prevented SQLAlchemy from
    batching the inserts.

    Only valid where the scope owns the trace_ids it writes, which a bootstrap
    replay does. The hash chain stays correct because the cache is seeded from
    the DB on first use of each trace and then tracks what we ourselves append.

    Async so it composes with `async with async_session() as s, bulk_audit_chain():`
    at the call sites that need it.
    """
    token = _bulk_audit_chain.set({})
    rows_token = _bulk_audit_rows.set([])
    try:
        yield
    finally:
        _bulk_audit_chain.reset(token)
        _bulk_audit_rows.reset(rows_token)


async def emit_audit_event(
    db: AsyncSession,
    *,
    trace_id: str,
    event_type: str,
    actor_type: str = "system",
    actor_id: Optional[str] = None,
    source_id: Optional[str] = None,
    parser_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    decision_name: Optional[str] = None,
    decision_reason_code: Optional[str] = None,
    decision_confidence: Optional[str] = None,
    decision_result: Optional[str] = None,
    data: Optional[dict[str, Any]] = None,
    retention_class: str = "operational",
    redaction_level: str = "standard",
    sensitivity: str = "internal",
    note: Optional[str] = None,
) -> str:
    """
    Emit an append-only audit event. This is intentionally best-effort from callers.
    """
    payload = data or {}
    event_id = uuid.uuid4().hex

    chain = _bulk_audit_chain.get()
    if chain is not None and trace_id in chain:
        prev = chain[trace_id]
    else:
        prev = await db.scalar(
            select(AuditEvent.record_hash)
            .where(AuditEvent.trace_id == trace_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(1)
        )
    body = {
        "event_id": event_id,
        "trace_id": trace_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "source_id": source_id,
        "parser_id": parser_id,
        "asset_id": asset_id,
        "finding_id": finding_id,
        "decision_name": decision_name,
        "decision_reason_code": decision_reason_code,
        "decision_confidence": decision_confidence,
        "decision_result": decision_result,
        "data": payload,
        "prev_record_hash": prev or "",
        "retention_class": retention_class,
        "redaction_level": redaction_level,
        "sensitivity": sensitivity,
        "note": note,
        "created_at": datetime.utcnow().isoformat(),
    }
    record_hash = hashlib.sha256(_stable_json(body).encode()).hexdigest()
    row = {
        "event_id": event_id,
        "trace_id": trace_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "source_id": source_id,
        "parser_id": parser_id,
        "asset_id": asset_id,
        "finding_id": finding_id,
        "decision_name": decision_name,
        "decision_reason_code": decision_reason_code,
        "decision_confidence": decision_confidence,
        "decision_result": decision_result,
        "data": payload,
        "prev_record_hash": prev,
        "record_hash": record_hash,
        "retention_class": retention_class,
        "redaction_level": redaction_level,
        "sensitivity": sensitivity,
        "note": note,
        "created_at": datetime.utcnow(),
    }
    if chain is not None:
        # We are now the tail of this trace's chain, so the next event on it
        # needs no lookup. Without this the cache never populates.
        chain[trace_id] = record_hash
    pending = _bulk_audit_rows.get()
    if pending is not None:
        # Queued for one executemany at the batch boundary.
        pending.append(row)
    else:
        db.add(AuditEvent(**row))
    if pending is None:
        # Flush so event row exists before mirroring to OTEL. Skipped in bulk
        # mode so the inserts batch; the OTEL span is telemetry, not evidence,
        # and the row still lands in the same transaction.
        await db.flush()
    mirrored = mirror_audit_event_to_otel(
        event_id=event_id,
        trace_id=trace_id,
        event_type=event_type,
        source_id=source_id,
        parser_id=parser_id,
        asset_id=asset_id,
        finding_id=finding_id,
        decision_name=decision_name,
        decision_reason_code=decision_reason_code,
        decision_confidence=decision_confidence,
        decision_result=decision_result,
    )
    if mirrored:
        METRICS.inc_audit_otel_mirror()
    else:
        METRICS.inc_audit_otel_mirror_failure()
    METRICS.inc_audit_event(event_type)
    logger.debug(
        "audit_event_emitted trace_id=%s event_type=%s source_id=%s parser_id=%s asset_id=%s finding_id=%s decision=%s reason=%s result=%s",
        trace_id,
        event_type,
        source_id or "",
        parser_id or "",
        asset_id or "",
        finding_id or "",
        decision_name or "",
        decision_reason_code or "",
        decision_result or "",
    )
    return event_id


async def create_daily_checkpoint(
    db: AsyncSession,
    *,
    checkpoint_date: str,
    retention_class: str = "operational",
) -> AuditLedgerCheckpoint:
    """Create/replace deterministic daily anchor hash for audit events."""
    rows = (
        (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.retention_class == retention_class)
                .where(
                    AuditEvent.created_at
                    >= datetime.fromisoformat(f"{checkpoint_date}T00:00:00")
                )
                .where(
                    AuditEvent.created_at
                    <= datetime.fromisoformat(f"{checkpoint_date}T23:59:59")
                )
                .order_by(AuditEvent.created_at.asc(), AuditEvent.event_id.asc())
            )
        )
        .scalars()
        .all()
    )
    chained = "".join(r.record_hash for r in rows)
    anchor_hash = (
        hashlib.sha256(chained.encode()).hexdigest()
        if chained
        else hashlib.sha256(b"").hexdigest()
    )

    existing = await db.scalar(
        select(AuditLedgerCheckpoint).where(
            AuditLedgerCheckpoint.checkpoint_date == checkpoint_date,
            AuditLedgerCheckpoint.retention_class == retention_class,
        )
    )
    if existing:
        existing.event_count = len(rows)
        existing.anchor_hash = anchor_hash
        return existing
    cp = AuditLedgerCheckpoint(
        id=uuid.uuid4().hex,
        checkpoint_date=checkpoint_date,
        retention_class=retention_class,
        event_count=len(rows),
        anchor_hash=anchor_hash,
    )
    db.add(cp)
    return cp
