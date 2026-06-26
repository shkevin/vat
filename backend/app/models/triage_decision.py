"""Durable triage decision — authoritative compliance state."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class TriageDecision(Base):
    """One decision per tenant + subject_key. Survives finding deletion."""

    __tablename__ = "triage_decisions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "subject_key", name="uq_triage_decisions_subject"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_key: Mapped[str] = mapped_column(String(512), nullable=False)
    subject_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False)
    suppression_scope: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewer_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attestation: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    decision_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    last_finding_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
