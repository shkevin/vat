"""Content-addressed storage for OpenSCAP raw evidence blobs."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class OpenSCAPEvidenceBlob(Base):
    __tablename__ = "openscap_evidence_blobs"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_xml: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

