"""Asset model — repos, containers, etc. from integrations."""

from typing import Optional

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Asset(Base):
    """
    Asset entity — code repos, containers, VMs, etc.
    Created by integrations so assets with zero findings appear in VAT.
    id = asset_key for grouping. branch/tag from integration; branches shown in asset page dropdown.
    """

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        String(512), primary_key=True
    )  # asset_key for grouping
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # repo | container
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # integration name
    branch: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # for repos
    tag: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # for containers
