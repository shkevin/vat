"""Normalized identifier facts extracted for correlation scoring."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FindingIdentifier(Base):
    __tablename__ = "finding_identifiers"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "namespace",
            "value",
            "source",
            name="uq_finding_identifier",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    namespace: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="ingest")
    metadata_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

