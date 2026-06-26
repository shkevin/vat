"""Materialized link between a durable decision and a current finding row."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DecisionFindingLink(Base):
    __tablename__ = "decision_finding_links"
    __table_args__ = (
        UniqueConstraint("decision_id", "finding_id", name="uq_decision_finding_link"),
    )

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)
    link_method: Mapped[str] = mapped_column(String(32), nullable=False)
    link_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    applied_decision_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    unlinked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
