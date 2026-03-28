"""Audit event emission and query helpers."""

from __future__ import annotations

import hashlib
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
    db.add(
        AuditEvent(
            event_id=event_id,
            trace_id=trace_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            source_id=source_id,
            parser_id=parser_id,
            asset_id=asset_id,
            finding_id=finding_id,
            decision_name=decision_name,
            decision_reason_code=decision_reason_code,
            decision_confidence=decision_confidence,
            decision_result=decision_result,
            data=payload,
            prev_record_hash=prev,
            record_hash=record_hash,
            retention_class=retention_class,
            redaction_level=redaction_level,
            sensitivity=sensitivity,
            note=note,
        )
    )
    # Flush so event row exists before mirroring to OTEL.
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
