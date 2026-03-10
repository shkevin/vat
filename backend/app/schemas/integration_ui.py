"""Integration settings UI schemas — schema-driven settings canvas.

Adapters declare their settings fields and appearance; the frontend renders consistently.
"""

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class IntegrationFieldSchema(BaseModel):
    """Single field in settings UI."""

    key: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., min_length=1, max_length=128)
    type: Literal["text", "password", "select", "boolean"] = "text"
    required: bool = False
    placeholder: Optional[str] = Field(default=None, max_length=128)
    options: Optional[list[dict]] = Field(default=None, description="For select: [{value, label}]")
    help_text: Optional[str] = Field(default=None, max_length=256)
    default: Optional[str | bool] = None


_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")


class IntegrationSettingsSchema(BaseModel):
    """What the settings canvas needs to render an integration."""

    adapter_key: str = Field(..., min_length=1, max_length=32)
    display_name: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=256)
    fields: list[IntegrationFieldSchema] = Field(default_factory=list)
    supports_test_connection: bool = False

    # Appearance — per-integration branding for cards and diagrams
    logo_url: Optional[str] = Field(default=None, max_length=512)
    brand_color: Optional[str] = Field(default=None, max_length=7)
    icon: Optional[str] = Field(default=None, max_length=32)

    @field_validator("brand_color")
    @classmethod
    def validate_hex_color(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        if not _HEX_COLOR.match(v):
            raise ValueError("brand_color must be hex format, e.g. #10B981")
        return v


class FlowTypeSchema(BaseModel):
    """Appearance for diagram edges/connections. VAT defines flow types."""

    color: str = Field(..., min_length=7, max_length=7)
    style: Literal["dashed", "solid"] = "dashed"
    label: Optional[str] = Field(default=None, max_length=64)

    @field_validator("color")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not _HEX_COLOR.match(v):
            raise ValueError("color must be hex format, e.g. #10B981")
        return v


# VAT-defined flow types for diagram edges. Centralized, not per-adapter.
FLOW_TYPES: dict[str, FlowTypeSchema] = {
    "ingest": FlowTypeSchema(color="#10B981", style="dashed", label="Ingest"),
    "sync_to_tracker": FlowTypeSchema(color="#5E6AD2", style="dashed", label="Sync"),
    "tracker_feedback": FlowTypeSchema(color="#8B5CF6", style="dashed", label="Comment"),
}
