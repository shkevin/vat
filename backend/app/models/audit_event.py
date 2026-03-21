"""Enterprise audit event model (append-only)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditEvent(Base):
    """Structured audit/observability event for ingest decision tracing."""

    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="system"
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    source_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True
    )
    parser_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    asset_id: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, index=True
    )
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, index=True
    )
    decision_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    decision_reason_code: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    decision_confidence: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    decision_result: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    prev_record_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    retention_class: Mapped[str] = mapped_column(
        String(32), nullable=False, default="operational"
    )
    redaction_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="standard"
    )
    sensitivity: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal"
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_events_trace_created", "trace_id", "created_at"),
        Index(
            "ix_audit_events_source_parser_created",
            "source_id",
            "parser_id",
            "created_at",
        ),
    )
