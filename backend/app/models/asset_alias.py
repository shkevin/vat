"""Manual asset alias overrides for canonical grouping."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetAlias(Base):
    """
    Source asset id -> canonical asset id override.
    Used when scanner/integration asset identification is wrong.
    """

    __tablename__ = "asset_aliases"

    source_asset_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    canonical_asset_id: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )
    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
