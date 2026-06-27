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


class DecisionRevisionRead(BaseModel):
    """One append-only revision of a decision (compliance evidence)."""

    model_config = ConfigDict(populate_by_name=True)

    revision: int
    actor_id: Optional[str] = Field(default=None, alias="actorId")
    reason: Optional[str] = None
    snapshot: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = Field(default=None, alias="createdAt")


class DecisionDetailRead(BaseModel):
    """Auditor drill-down: a decision with its full revision history and live links."""

    model_config = ConfigDict(populate_by_name=True)

    decision_id: str = Field(alias="decisionId")
    tenant_id: str = Field(alias="tenantId")
    subject_key: str = Field(alias="subjectKey")
    finding_type: str = Field(alias="findingType")
    status: str
    decision_version: int = Field(alias="decisionVersion")
    justification: Optional[str] = None
    compensating_controls: Optional[str] = Field(default=None, alias="compensatingControls")
    reviewer_note: Optional[str] = Field(default=None, alias="reviewerNote")
    attestation: Optional[dict[str, Any]] = None
    identity_snapshot: Optional[dict[str, Any]] = Field(default=None, alias="identitySnapshot")
    created_by: str = Field(alias="createdBy")
    created_at: Optional[str] = Field(default=None, alias="createdAt")
    updated_by: Optional[str] = Field(default=None, alias="updatedBy")
    updated_at: Optional[str] = Field(default=None, alias="updatedAt")
    linked_finding_ids: list[str] = Field(default_factory=list, alias="linkedFindingIds")
    revisions: list[DecisionRevisionRead] = Field(default_factory=list)
