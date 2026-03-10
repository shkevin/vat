"""User schemas."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    tenant_id: Optional[str] = None
    email: EmailStr
    role: str = Field(..., pattern=r"^(admin|reviewer|read_only)$")


class UserUpdate(BaseModel):
    tenant_id: Optional[str] = None
    role: Optional[str] = Field(None, pattern=r"^(admin|reviewer|read_only)$")


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: Optional[str]
    email: str
    role: str
