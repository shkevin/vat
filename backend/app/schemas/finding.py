"""Finding request/response schemas."""

from datetime import datetime
from typing import Optional

try:
    from pydantic import BaseModel, ConfigDict

    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseModel

    _PYDANTIC_V2 = False

from app.models.finding import FindingType, Severity, Status, SuppressionScope

def _external_links_to_camel(links: list) -> list:
    """Convert external_links items to camelCase for frontend API."""
    out = []
    for link in links:
        if not isinstance(link, dict):
            out.append(link)
            continue
        out.append({
            "adapterKey": link.get("adapter_key"),
            "kind": link.get("kind"),
            "issueId": link.get("issue_id"),
            "url": link.get("url"),
            "createdAt": link.get("created_at"),
            "lastSyncedAt": link.get("last_synced_at"),
        })
    return out


# Map backend enum to frontend display format
STATUS_DISPLAY = {
    "SyncedToTracker": "Synced to Tracker",
    "InReview": "In Review",
    "RiskAccepted": "Risk Accepted",
    "FalsePositive": "False Positive",
    "NotApplicable": "Not Applicable",
}


class FindingBase(BaseModel):
    finding_type: FindingType
    cve_id: str
    severity: Severity
    status: Status
    component_base: Optional[str] = None
    component: Optional[str] = None
    image: Optional[str] = None
    branch: Optional[str] = None
    tag: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    team: Optional[str] = None
    owner: Optional[str] = None
    control_ref: Optional[str] = None
    sla_due: Optional[str] = None
    cvss: Optional[str] = None
    epss: Optional[str] = None
    justification: Optional[str] = None
    compensating_controls: Optional[str] = None
    reviewer_note: Optional[str] = None
    tracker_comment: bool = False


class FindingCreate(FindingBase):
    fingerprint_id: str
    sources: list[dict] = []
    regression_of: Optional[list[str]] = None
    regression_count: int = 0
    audit: list[dict] = []


class FindingRead(BaseModel):
    if _PYDANTIC_V2:
        model_config = ConfigDict(from_attributes=True)
    else:
        class Config:
            orm_mode = True

    id: str
    finding_type: FindingType
    fingerprint_id: str
    cve_id: str
    severity: Severity
    status: Status
    component_base: Optional[str] = None
    component: Optional[str] = None
    image: Optional[str] = None
    branch: Optional[str] = None
    tag: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    team: Optional[str] = None
    owner: Optional[str] = None
    tracker_id: Optional[str] = None  # Derived from external_links (first tracker link)
    control_ref: Optional[str] = None
    sla_due: Optional[str] = None
    cvss: Optional[str] = None
    epss: Optional[str] = None
    justification: Optional[str] = None
    compensating_controls: Optional[str] = None
    reviewer_note: Optional[str] = None
    tracker_comment: bool = False
    sources: list[dict] = []
    suppression_scope: Optional[SuppressionScope] = None
    attestation: Optional[dict] = None
    regression_of: Optional[list[str]] = None
    regression_count: int = 0
    previous_status: Optional[str] = None
    audit: list[dict] = []
    archived: bool = False
    archived_at: Optional[datetime] = None
    archived_reason: Optional[str] = None
    source_file_url: Optional[str] = None
    source_issue_group_id: Optional[str] = None
    aikido_source_id: Optional[str] = None
    external_links: list = []
    file_path: Optional[str] = None
    line: Optional[int] = None
    snippet_masked: Optional[str] = None
    rule_id: Optional[str] = None
    cwe_id: Optional[str] = None
    ecosystem: Optional[str] = None
    secret_type: Optional[str] = None
    resource: Optional[str] = None
    correlation_key: Optional[str] = None
    correlation_confidence: Optional[str] = None
    correlated_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    first_detected_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None

    def to_api_dict(self) -> dict:
        """Convert to camelCase dict for frontend API."""
        return {
            "id": self.id,
            "findingType": self.finding_type.value,
            "fingerprintId": self.fingerprint_id,
            "cveId": self.cve_id,
            "severity": self.severity.value,
            "status": STATUS_DISPLAY.get(self.status.value, self.status.value),
            "componentBase": self.component_base,
            "component": self.component,
            "image": self.image,
            "branch": self.branch,
            "tag": self.tag,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "team": self.team,
            "owner": self.owner,
            "trackerId": self.tracker_id,
            "externalLinks": _external_links_to_camel(self.external_links or []),
            "controlRef": self.control_ref,
            "slaDue": self.sla_due,
            "cvss": self.cvss,
            "epss": self.epss,
            "justification": self.justification,
            "compensatingControls": self.compensating_controls,
            "reviewerNote": self.reviewer_note,
            "trackerComment": self.tracker_comment,
            "sources": self.sources,
            "suppressionScope": self.suppression_scope.value if self.suppression_scope else None,
            "attestation": self.attestation,
            "regressionOf": self.regression_of,
            "regressionCount": self.regression_count,
            "previousStatus": STATUS_DISPLAY.get(self.previous_status or "", self.previous_status) if self.previous_status else None,
            "audit": self.audit,
            "archived": self.archived,
            "archivedAt": self.archived_at.isoformat() if self.archived_at else None,
            "archivedReason": self.archived_reason,
            "sourceFileUrl": self.source_file_url,
            "sourceIssueGroupId": self.source_issue_group_id,
            "aikidoSourceId": self.aikido_source_id,
            "filePath": self.file_path,
            "line": self.line,
            "snippetMasked": self.snippet_masked,
            "ruleId": self.rule_id,
            "cweId": self.cwe_id,
            "ecosystem": self.ecosystem,
            "secretType": self.secret_type,
            "resource": self.resource,
            "correlationKey": self.correlation_key,
            "correlationConfidence": self.correlation_confidence,
            "correlatedTo": self.correlated_to,
            "created": self.created_at.isoformat() if self.created_at else None,
            "firstDetectedAt": self.first_detected_at.isoformat() if self.first_detected_at else None,
            "closedAt": self.closed_at.isoformat() if self.closed_at else None,
        }


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    justification: Optional[str] = None
    compensating_controls: Optional[str] = None
    reviewer_note: Optional[str] = None
    suppression_scope: Optional[str] = None
    attestation: Optional[dict] = None


class FindingArchive(BaseModel):
    reason: str


class FindingRevert(BaseModel):
    reason: str


class FindingBulkUpdate(BaseModel):
    ids: list[str]
    status: str
    justification: str = ""
