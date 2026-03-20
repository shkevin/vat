"""Sync configuration schemas — formal contract for source and tracker config."""

from enum import Enum
from typing import Optional

try:
    from pydantic import BaseModel, ConfigDict, Field, model_validator

    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseModel, Field, root_validator

    _PYDANTIC_V2 = False


class SourceAuthType(str, Enum):
    """Source authentication/delivery type."""

    WEBHOOK = "webhook"  # Push via webhook, can sync back
    PUSH = "push"  # One-way ingest only (CI, manual)


class SourceConfig(BaseModel):
    """Formal contract for source configuration. All sources must conform."""

    name: str
    adapter: str
    auth_type: SourceAuthType = Field(default=SourceAuthType.WEBHOOK, alias="authType")
    supports_outbound_sync: bool = Field(default=True, alias="supportsOutboundSync")

    if _PYDANTIC_V2:
        model_config = ConfigDict(
            populate_by_name=True,
            extra="ignore",  # Ignore unknown keys from legacy config
        )
    else:
        class Config:
            allow_population_by_field_name = True
            extra = "ignore"

    if _PYDANTIC_V2:
        @model_validator(mode="after")
        def push_implies_no_outbound(self):
            """auth_type=PUSH must have supports_outbound_sync=False."""
            if self.auth_type == SourceAuthType.PUSH and self.supports_outbound_sync:
                raise ValueError("auth_type=push requires supports_outbound_sync=False")
            return self
    else:
        @root_validator
        def push_implies_no_outbound(cls, values):
            if (
                values.get("auth_type") == SourceAuthType.PUSH
                and values.get("supports_outbound_sync")
            ):
                raise ValueError("auth_type=push requires supports_outbound_sync=False")
            return values


class TrackerConfig(BaseModel):
    """Formal contract for tracker configuration."""

    adapter: str
    team_id: Optional[str] = None
    supports_create_issue: bool = True
    supports_post_comment: bool = True
    supports_list_issues: bool = False
