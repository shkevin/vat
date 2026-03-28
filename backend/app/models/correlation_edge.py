"""Non-destructive correlation edges between findings (undirected)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class CorrelationEdge(Base):
    __tablename__ = "correlation_edges"
    __table_args__ = (
        UniqueConstraint(
            "finding_id_a",
            "finding_id_b",
            name="uq_correlation_edges_pair",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id_a: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    finding_id_b: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False, default="same_rule")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    operation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    removed_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    removed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    remove_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

