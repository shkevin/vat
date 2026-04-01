"""Vulnerability feed refresh run metadata."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VulnFeedRun(Base):
    __tablename__ = "vuln_feed_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="completed", index=True
    )  # running | completed | failed
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
