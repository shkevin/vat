"""Tenant schemas."""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class TenantCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=128)
    auth_method: str = Field(default="local", pattern=r"^(local|google|generic_oidc|saml)$")


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    auth_method: str = "local"
    auth_config: Optional[dict[str, Any]] = None


class TenantUpdate(BaseModel):
    auth_method: Optional[str] = Field(default=None, pattern=r"^(local|google|generic_oidc|saml)$")
