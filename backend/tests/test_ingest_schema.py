"""Tests for canonical ingest schema."""

import pytest
from pydantic import ValidationError

from app.schemas.ingest import (
    CanonicalFindingPayload,
    CanonicalFindingType,
    CanonicalIngestRequest,
    CanonicalSeverity,
)


def test_canonical_finding_payload_required_fields():
    p = CanonicalFindingPayload(
        cve_id="CVE-2024-1234",
        severity="High",
        description="test",
        component="lib-x 1.0",
        image="my-repo",
    )
    assert p.cve_id == "CVE-2024-1234"
    assert p.severity == CanonicalSeverity.HIGH
    assert p.description == "test"
    assert p.finding_type == CanonicalFindingType.SCA


def test_canonical_finding_payload_severity_normalization():
    p = CanonicalFindingPayload(cve_id="x", severity="critical", description="", file_path="src", image="repo")
    assert p.severity == CanonicalSeverity.CRITICAL
    p2 = CanonicalFindingPayload(cve_id="x", severity="info", description="", file_path="src", branch="main")
    assert p2.severity == CanonicalSeverity.INFORMATIONAL


def test_canonical_finding_payload_optional_fields():
    p = CanonicalFindingPayload(
        cve_id="CVE-2024-1234",
        severity="High",
        description="desc",
        component="lib-x 1.2.3",
        cvss="8.5",
        file_path="package.json",
        image="my-repo",
    )
    assert p.component == "lib-x 1.2.3"
    assert p.cvss == "8.5"
    assert p.file_path == "package.json"


def test_canonical_finding_payload_missing_cve_id():
    with pytest.raises(ValidationError):
        CanonicalFindingPayload(cve_id="", severity="High", description="test", component="x", image="repo")


def test_canonical_finding_payload_requires_asset_context():
    """Finding must have at least one of: image, branch, tag (for asset-scoped grouping)."""
    with pytest.raises(ValidationError, match="image, branch, tag"):
        CanonicalFindingPayload(cve_id="CVE-1", severity="High", description="test")


def test_canonical_ingest_request():
    req = CanonicalIngestRequest(
        source="trivy",
        findings=[
            CanonicalFindingPayload(
                cve_id="CVE-2024-1234",
                severity="High",
                description="test",
                component="pkg 1.0",
                image="my-repo",
            ),
        ],
    )
    assert req.source == "trivy"
    assert len(req.findings) == 1
    assert req.findings[0].cve_id == "CVE-2024-1234"


def test_canonical_ingest_request_empty_findings():
    with pytest.raises(ValidationError):
        CanonicalIngestRequest(source="trivy", findings=[])
