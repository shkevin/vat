"""Audit API — enterprise decision trace and evidence export helpers."""

from __future__ import annotations

import json
from datetime import datetime
from io import BytesIO
from typing import Optional
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_admin
from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.schemas.auth import UserContext
from app.services.audit_events import create_daily_checkpoint, emit_audit_event

router = APIRouter()


def _apply_filters(
    q,
    *,
    trace_id: Optional[str],
    source_id: Optional[str],
    parser_id: Optional[str],
    asset_id: Optional[str],
    finding_id: Optional[str],
    event_type: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
):
    clauses = []
    if trace_id:
        clauses.append(AuditEvent.trace_id == trace_id)
    if source_id:
        clauses.append(AuditEvent.source_id == source_id)
    if parser_id:
        clauses.append(AuditEvent.parser_id == parser_id)
    if asset_id:
        clauses.append(AuditEvent.asset_id == asset_id)
    if finding_id:
        clauses.append(AuditEvent.finding_id == finding_id)
    if event_type:
        clauses.append(AuditEvent.event_type == event_type)
    if date_from:
        clauses.append(AuditEvent.created_at >= datetime.fromisoformat(date_from))
    if date_to:
        clauses.append(AuditEvent.created_at <= datetime.fromisoformat(date_to))
    if clauses:
        q = q.where(and_(*clauses))
    return q


@router.get("/events")
async def list_audit_events(
    trace_id: str | None = None,
    source_id: str | None = None,
    parser_id: str | None = None,
    asset_id: str | None = None,
    finding_id: str | None = None,
    event_type: str | None = None,
    date_from: str | None = Query(default=None, description="ISO datetime"),
    date_to: str | None = Query(default=None, description="ISO datetime"),
    limit: int = Query(default=500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    q = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    q = _apply_filters(
        q,
        trace_id=trace_id,
        source_id=source_id,
        parser_id=parser_id,
        asset_id=asset_id,
        finding_id=finding_id,
        event_type=event_type,
        date_from=date_from,
        date_to=date_to,
    )
    rows = (await db.execute(q)).scalars().all()
    return {
        "count": len(rows),
        "events": [
            {
                "eventId": r.event_id,
                "traceId": r.trace_id,
                "eventType": r.event_type,
                "createdAt": r.created_at.isoformat() if r.created_at else None,
                "sourceId": r.source_id,
                "parserId": r.parser_id,
                "assetId": r.asset_id,
                "findingId": r.finding_id,
                "decisionName": r.decision_name,
                "decisionReasonCode": r.decision_reason_code,
                "decisionConfidence": r.decision_confidence,
                "decisionResult": r.decision_result,
                "recordHash": r.record_hash,
                "prevRecordHash": r.prev_record_hash,
                "data": r.data or {},
            }
            for r in rows
        ],
    }


@router.get("/export")
async def export_audit_events(
    trace_id: str | None = None,
    source_id: str | None = None,
    parser_id: str | None = None,
    asset_id: str | None = None,
    finding_id: str | None = None,
    event_type: str | None = None,
    date_from: str | None = Query(default=None, description="ISO datetime"),
    date_to: str | None = Query(default=None, description="ISO datetime"),
    limit: int = Query(default=5000, ge=1, le=20000),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    q = select(AuditEvent).order_by(AuditEvent.created_at.asc()).limit(limit)
    q = _apply_filters(
        q,
        trace_id=trace_id,
        source_id=source_id,
        parser_id=parser_id,
        asset_id=asset_id,
        finding_id=finding_id,
        event_type=event_type,
        date_from=date_from,
        date_to=date_to,
    )
    rows = (await db.execute(q)).scalars().all()
    events = [
        {
            "event_id": r.event_id,
            "trace_id": r.trace_id,
            "event_type": r.event_type,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "source_id": r.source_id,
            "parser_id": r.parser_id,
            "asset_id": r.asset_id,
            "finding_id": r.finding_id,
            "decision_name": r.decision_name,
            "decision_reason_code": r.decision_reason_code,
            "decision_confidence": r.decision_confidence,
            "decision_result": r.decision_result,
            "record_hash": r.record_hash,
            "prev_record_hash": r.prev_record_hash,
            "data": r.data or {},
        }
        for r in rows
    ]
    manifest = {
        "schemaVersion": "v1",
        "generatedAt": datetime.utcnow().isoformat(),
        "count": len(events),
        "filters": {
            "traceId": trace_id,
            "sourceId": source_id,
            "parserId": parser_id,
            "assetId": asset_id,
            "findingId": finding_id,
            "eventType": event_type,
            "dateFrom": date_from,
            "dateTo": date_to,
            "limit": limit,
        },
    }
    buf = BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("audit-events.json", json.dumps(events, indent=2))
    if rows:
        await emit_audit_event(
            db,
            trace_id=rows[0].trace_id,
            event_type="export.audit_bundle.generated",
            actor_type="user",
            actor_id=_ctx.email or _ctx.user_id,
            decision_name="audit_export",
            decision_reason_code="manual_export",
            decision_confidence="high",
            decision_result="generated",
            data={"count": len(events)},
            retention_class="compliance",
        )
        await db.commit()
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=audit-events-export.zip"},
    )


@router.post("/checkpoints/daily")
async def create_checkpoint(
    checkpoint_date: str = Query(description="UTC date in YYYY-MM-DD format"),
    retention_class: str = Query(default="operational"),
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    cp = await create_daily_checkpoint(
        db,
        checkpoint_date=checkpoint_date,
        retention_class=retention_class,
    )
    await db.commit()
    return {
        "id": cp.id,
        "checkpointDate": cp.checkpoint_date,
        "retentionClass": cp.retention_class,
        "eventCount": cp.event_count,
        "anchorHash": cp.anchor_hash,
        "createdAt": cp.created_at.isoformat() if cp.created_at else None,
    }

