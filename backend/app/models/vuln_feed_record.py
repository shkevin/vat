"""Normalized vulnerability records ingested from external public feeds."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VulnFeedRecord(Base):
    __tablename__ = "vuln_feed_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    record_key: Mapped[str] = mapped_column(String(256), nullable=False)
    vulnerability_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True
    )
    aliases: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    package_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    __table_args__ = (
        UniqueConstraint("source", "record_key", name="uq_vuln_feed_records_source_key"),
        Index("ix_vuln_feed_records_source_vuln", "source", "vulnerability_id"),
    )
