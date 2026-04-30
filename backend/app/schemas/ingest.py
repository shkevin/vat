"""Ingest schemas — re-exports VAT schemas for API compatibility."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity

# Aliases for parsers and API that still use old names
CanonicalFindingPayload = VatFindingSchema
CanonicalFindingType = VatFindingType
CanonicalSeverity = VatSeverity


class CanonicalIngestRequest(BaseModel):
    """API request body for POST /api/ingest.

    ``extra='forbid'`` rejects any unknown top-level field. If a future
    schema add accidentally collides with a server-only column name (e.g.
    ``id``, ``tenant_id``, ``fingerprint_id``), unknown supply is now a
    422 instead of silently being dropped — surfacing the contract drift
    early.
    """

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(
        default=None, max_length=128, description="Report name for audit"
    )
    source: str = Field(
        default="api",
        max_length=64,
        description="Source identifier (e.g. trivy, github-ci, manual)",
    )
    findings: list[VatFindingSchema] = Field(..., min_length=1, max_length=1000)
