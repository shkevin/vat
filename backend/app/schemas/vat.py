"""VAT canonical schemas — central contract for all sync flows.

All sources and trackers map their native formats to/from these schemas.
Security: field length limits, validation, no credential storage.
"""

from enum import Enum
from typing import Literal, Optional

try:
    from pydantic import BaseModel, Field, field_validator, model_validator

    _PYDANTIC_V2 = True
except (
    ImportError
):  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseModel, Field, root_validator, validator

    _PYDANTIC_V2 = False

    def field_validator(*fields, mode="after", **kwargs):
        return validator(*fields, pre=(mode == "before"), allow_reuse=True, **kwargs)


# --- Enums (VAT canonical) ---


def _sanitize_untrusted_text(value: str) -> str:
    """Remove control chars that break DB/storage and logs.

    PostgreSQL text/json cannot store NUL bytes, so strip ``\\x00``.
    Keep common whitespace (tab/newline/carriage return), drop other C0 controls.
    """
    if not isinstance(value, str):
        return value
    if not value:
        return value
    cleaned = value.replace("\x00", "")
    # Preserve readability while removing non-printable control chars.
    return "".join(
        ch for ch in cleaned if ch in ("\t", "\n", "\r") or ord(ch) >= 32
    )


def _sanitize_untrusted_value(value):
    """Recursively sanitize string-like payload content."""
    if isinstance(value, str):
        return _sanitize_untrusted_text(value)
    if isinstance(value, list):
        return [_sanitize_untrusted_value(v) for v in value]
    if isinstance(value, dict):
        sanitized: dict = {}
        for k, v in value.items():
            sk = _sanitize_untrusted_text(k) if isinstance(k, str) else k
            sanitized[sk] = _sanitize_untrusted_value(v)
        return sanitized
    return value


class VatSeverity(str, Enum):
    """Severity levels for VAT findings."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class VatFindingType(str, Enum):
    """Finding types per PRD §5.1.3."""

    SCA = "SCA"  # Software Composition Analysis (was CVE — CVE is an identifier, not a classifier)
    SECRET = "Secret"
    IAC = "IaC"
    SAST = "SAST"
    LICENSE = "License"


# --- Inbound: External → VAT ---


class VatFindingSchema(BaseModel):
    """VAT canonical finding. All sources must map to this."""

    # Required
    cve_id: str = Field(
        ..., min_length=1, max_length=128, description="CVE ID, secret ID, or rule ID"
    )
    severity: VatSeverity
    description: str = Field(default="", max_length=10000)

    # Optional — component/asset context
    component: Optional[str] = Field(default=None, max_length=512)
    component_base: Optional[str] = Field(default=None, max_length=256)
    image: Optional[str] = Field(default=None, max_length=256)
    branch: Optional[str] = Field(default=None, max_length=128)
    tag: Optional[str] = Field(default=None, max_length=128)
    observed_container_tags: Optional[list[str]] = Field(
        default=None,
        description=(
            "Distinct image tags for this issue (e.g. Aikido instances/locations). "
            "Used at ingest to populate asset_observed_tags for the UI; not part of fingerprint."
        ),
    )
    image_digest: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Manifest digest sha256:hex — same digest = same image (multi-tag)",
    )
    file_path: Optional[str] = Field(default=None, max_length=1024)
    line: Optional[int] = Field(default=None, ge=1)
    source_file_url: Optional[str] = Field(default=None, max_length=2048)
    snippet_masked: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Line preview with sensitive parts masked (e.g. ***REDACTED***)",
    )

    # Optional — grouping (parsers populate when available; used for derived grouping)
    rule_id: Optional[str] = Field(
        default=None, max_length=256, description="SAST/IaC/Secret rule or check ID"
    )
    cwe_id: Optional[str] = Field(
        default=None, max_length=32, description="CWE-XXX for SAST grouping"
    )
    ecosystem: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Package ecosystem: npm, pypi, go, debian, etc.",
    )
    secret_type: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Secret category, e.g. AWS Key, Generic Secret",
    )
    resource: Optional[str] = Field(
        default=None,
        max_length=512,
        description="IaC resource path/ARN for subissue display",
    )

    # Optional — metadata
    source_issue_id: Optional[str] = Field(default=None, max_length=128)
    source_issue_group_id: Optional[str] = Field(
        default=None, max_length=64
    )  # Aikido group_id when available
    source_issue_url: Optional[str] = Field(
        default=None, max_length=2048
    )  # Deep link to view in source (e.g. Aikido dashboard)
    status: Optional[str] = Field(default=None, max_length=32)
    first_detected_at: Optional[str] = Field(default=None, max_length=64)
    closed_at: Optional[str] = Field(default=None, max_length=64)
    title: Optional[str] = Field(default=None, max_length=512)
    finding_type: VatFindingType = VatFindingType.SCA
    cvss: Optional[str] = Field(default=None, max_length=16)
    epss: Optional[str] = Field(default=None, max_length=16)
    team: Optional[str] = Field(default=None, max_length=128)
    owner: Optional[str] = Field(default=None, max_length=256)
    references: Optional[list[str]] = Field(default=None, max_length=50)

    # Optional — scan/session and identity metadata (Phase 1 identity model)
    scan_session_id: Optional[str] = Field(default=None, max_length=64)
    scanner_version: Optional[str] = Field(default=None, max_length=64)
    content_version: Optional[str] = Field(default=None, max_length=64)
    benchmark_id: Optional[str] = Field(default=None, max_length=256)
    benchmark_family: Optional[str] = Field(default=None, max_length=128)
    profile_scope: Optional[str] = Field(default=None, max_length=256)
    stable_rule_key: Optional[str] = Field(default=None, max_length=256)
    result_state: Optional[str] = Field(default=None, max_length=32)
    needs_family_classification: Optional[bool] = Field(default=None)
    # Backend-owned enrichment/provenance metadata (optional, internal-first).
    provided_identifiers: Optional[dict] = Field(default=None)
    derived_identifiers: Optional[dict] = Field(default=None)
    enrichment_meta: Optional[dict] = Field(default=None)
    partial_fingerprints: Optional[dict[str, str]] = Field(
        default=None,
        description="SARIF result.partialFingerprints for stable static dedup/correlation",
    )
    scanner_identity: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Opaque stable id from the scanner when not using SARIF fingerprints",
    )

    @field_validator("*", mode="before")
    @classmethod
    def sanitize_untrusted_inputs(cls, v):
        return _sanitize_untrusted_value(v)

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, v: str) -> str:
        return v.strip() if v else "unknown"

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v) -> VatSeverity:
        if isinstance(v, VatSeverity):
            return v
        s = str(v).lower()
        mapping = {
            "critical": VatSeverity.CRITICAL,
            "high": VatSeverity.HIGH,
            "medium": VatSeverity.MEDIUM,
            "low": VatSeverity.LOW,
            "info": VatSeverity.INFORMATIONAL,
            "informational": VatSeverity.INFORMATIONAL,
        }
        return mapping.get(s, VatSeverity.MEDIUM)

    # Asset context can be sparse at ingest time; backend enrichment and resolver
    # now own deriving canonical asset identity for correlation.


class VatTrackerCommentUpdate(BaseModel):
    """Parsed engineer comment from tracker. Tracker adapters produce this."""

    cve_id: str = Field(..., min_length=1, max_length=128)
    status: str = Field(..., max_length=64)
    justification: str = Field(default="", max_length=10000)
    compensating_controls: str = Field(default="", max_length=2000)
    tracker_issue_id: str = Field(..., max_length=64)
    tracker_comment_id: Optional[str] = Field(default=None, max_length=64)


# --- Outbound: VAT → External ---


class VatSourceIgnoreRequest(BaseModel):
    """Tell source to ignore/suppress issue."""

    issue_id: str = Field(..., min_length=1, max_length=128)
    scope: Literal["global", "contextual"] = "contextual"

    @field_validator("issue_id")
    @classmethod
    def sanitize_issue_id(cls, v: str) -> str:
        """Prevent path traversal or injection in issue_id."""
        return v.strip()[:128]


class VatSourceUnignoreRequest(BaseModel):
    """Tell source to unignore issue (e.g. on Reopened)."""

    issue_id: str = Field(..., min_length=1, max_length=128)

    @field_validator("issue_id")
    @classmethod
    def sanitize_issue_id(cls, v: str) -> str:
        return v.strip()[:128]


class LabelConfig(BaseModel):
    """Label name and optional color for Linear (used when auto-creating)."""

    name: str = Field(..., min_length=1, max_length=64)
    color: Optional[str] = Field(default=None, max_length=20)


class VatTrackerCreateIssueRequest(BaseModel):
    """Create tracker issue for finding."""

    finding: dict = Field(
        ..., description="Finding snapshot: cve_id, title, severity, component, etc."
    )
    template: str = Field(..., min_length=1, max_length=10000)
    label_names: Optional[list[str]] = Field(default=None, max_length=50)
    label_configs: Optional[list[LabelConfig]] = Field(
        default=None, description="Name+color for auto-creation"
    )

    @field_validator("finding")
    @classmethod
    def validate_finding(cls, v: dict) -> dict:
        """Ensure finding is a dict with required identifier."""
        if not isinstance(v, dict):
            raise ValueError("finding must be a dict")
        if not (v.get("cve_id") or v.get("cveId")):
            raise ValueError("finding must have cve_id or cveId")
        return v


class VatTrackerPostDecisionRequest(BaseModel):
    """Post reviewer decision to tracker."""

    tracker_issue_id: str = Field(..., min_length=1, max_length=64)
    body: str = Field(..., max_length=10000)


class VatTrackerUpdateIssueRequest(BaseModel):
    """Push VAT field changes to tracker issue."""

    issue_id: str = Field(..., min_length=1, max_length=64)
    finding: dict = Field(
        ..., description="Finding snapshot: cve_id, title, severity, etc."
    )
    changed_fields: list[str] = Field(default_factory=list, max_length=20)
    label_names: Optional[list[str]] = Field(default=None, max_length=50)
    label_configs: Optional[list[LabelConfig]] = Field(
        default=None, description="Name+color for auto-creation"
    )
    issue_uuid: Optional[str] = Field(
        default=None, description="Linear UUID; avoids resolve query when present"
    )
