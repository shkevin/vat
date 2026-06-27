"""Maps alternate subject keys to a canonical triage decision subject_key."""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DecisionSubjectAlias(Base):
    __tablename__ = "decision_subject_aliases"
    __table_args__ = ({"schema": "decisions"},)

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alias_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
