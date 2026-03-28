"""Dynamic crosswalk entries for identifier resolution."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class CrosswalkEntry(Base):
    __tablename__ = "crosswalk_entries"
    __table_args__ = (
        UniqueConstraint(
            "from_namespace",
            "from_value",
            "to_namespace",
            "to_value",
            "source",
            "source_version",
            name="uq_crosswalk_entries_mapping",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    from_namespace: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    from_value: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    to_namespace: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    to_value: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    disabled_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    disabled_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

