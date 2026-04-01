"""Latest status snapshot per vulnerability feed source."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VulnFeedSource(Base):
    __tablename__ = "vuln_feed_sources"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="never", index=True
    )
    last_attempt_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_etag: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    last_checksum: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    last_item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
