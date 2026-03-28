"""Persistent review decisions for asset merge suggestions."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetMergeReview(Base):
    __tablename__ = "asset_merge_reviews"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source_asset_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_asset_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )  # pending | approved | denied
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    strategy: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

