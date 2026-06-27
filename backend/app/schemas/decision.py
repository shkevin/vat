"""Decision ledger API schemas."""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class WaiverDecisionRead(BaseModel):
    """Risk-accepted decision from the durable ledger."""

    model_config = ConfigDict(populate_by_name=True)

    decision_id: str = Field(alias="decisionId")
    subject_key: str = Field(alias="subjectKey")
    tenant_id: str = Field(alias="tenantId")
    finding_id: Optional[str] = Field(default=None, alias="findingId")
    linked: bool = False
    finding_type: str = Field(alias="findingType")
    status: str
    cve_id: str = Field(alias="cveId")
    title: Optional[str] = None
    severity: Optional[str] = None
    component: Optional[str] = None
    image: Optional[str] = None
    rule_id: Optional[str] = Field(default=None, alias="ruleId")
    control_ref: Optional[str] = Field(default=None, alias="controlRef")
    attestation: Optional[dict[str, Any]] = None
    justification: Optional[str] = None
    decision_version: int = Field(alias="decisionVersion")
    updated_at: Optional[str] = Field(default=None, alias="updatedAt")


class DecisionBackfillResult(BaseModel):
    created: int = 0
    skipped: int = 0
    scanned: int = 0
