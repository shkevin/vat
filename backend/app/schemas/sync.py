"""Sync configuration schemas — formal contract for source and tracker config."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


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

    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",  # Ignore unknown keys from legacy config
    )

    @model_validator(mode="after")
    def push_implies_no_outbound(self):
        """auth_type=PUSH must have supports_outbound_sync=False."""
        if self.auth_type == SourceAuthType.PUSH and self.supports_outbound_sync:
            raise ValueError("auth_type=push requires supports_outbound_sync=False")
        return self


class TrackerConfig(BaseModel):
    """Formal contract for tracker configuration."""

    adapter: str
    team_id: Optional[str] = None
    supports_create_issue: bool = True
    supports_post_comment: bool = True
    supports_list_issues: bool = False
