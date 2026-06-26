"""Tests for ingest asset-type transform."""

from app.api.ingest import _apply_asset_type_transform, _resolve_parser
from app.schemas.vat import VatFindingSchema
from app.services.risk_scoring import merge_source_risk_scoring


def test_apply_asset_type_transform_package_only():
    """Package source: image moved to component."""
    p = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        image="package.json>foo",
    )
    out = _apply_asset_type_transform(p, "package")
    assert out.image is None
    assert out.component == "package.json>foo"
    assert out.tag == "package.json>foo"


def test_apply_asset_type_transform_package_preserves_existing_tag():
    """Package mode should not overwrite caller-provided tag."""
    p = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        image="vat-codebase",
        tag="2026-03-30_111245",
    )
    out = _apply_asset_type_transform(p, "package")
    assert out.image is None
    assert out.component == "vat-codebase"
    assert out.tag == "2026-03-30_111245"


def test_apply_asset_type_transform_container_plus_package_preserved():
    """Container+package: preserve both so packages group under image."""
    p = VatFindingSchema(
        cve_id="CVE-2025-68121",
        severity="Critical",
        description="x",
        image="kamiwaza-bundle:kamiwaza-images",
        component="stdlib v1.25.0",
    )
    out = _apply_asset_type_transform(p, "package")
    assert out.image == "kamiwaza-bundle:kamiwaza-images"
    assert out.component == "stdlib v1.25.0"


def test_apply_asset_type_transform_skip_when_not_package():
    """Non-package source: no transform."""
    p = VatFindingSchema(
        cve_id="CVE-1",
        severity="High",
        description="x",
        image="my-image:latest",
        component="pkg 1.0",
    )
    out = _apply_asset_type_transform(p, "container")
    assert out.image == "my-image:latest"
    assert out.component == "pkg 1.0"


def test_vat_schema_sanitizes_null_bytes_and_control_chars():
    """Ingest payload text should be DB-safe (no NUL bytes)."""
    p = VatFindingSchema(
        cve_id="CVE-\x000001",
        severity="High",
        description="hello\x00world\x01",
        image="repo\x00:tag",
        file_path="frontend/.next/cache/\x00bundle.pack",
        snippet_masked="tok\x00en\tok\nkeep",
        partial_fingerprints={"primary\x00": "ab\x00cd"},
    )
    assert p.cve_id == "CVE-0001"
    assert p.description == "helloworld"
    assert p.image == "repo:tag"
    assert p.file_path == "frontend/.next/cache/bundle.pack"
    assert p.snippet_masked == "token\tok\nkeep"
    assert p.partial_fingerprints == {"primary": "abcd"}


def test_vat_schema_accepts_structured_risk_scoring():
    """Scanner and reviewer scoring inputs should travel through canonical ingest."""
    p = VatFindingSchema(
        cve_id="CVE-2024-23342",
        severity="High",
        description="python-ecdsa: vulnerable to the Minerva attack",
        component="ecdsa 0.19.2",
        risk_scoring={
            "source": {
                "source": "CVSS",
                "cvssVersion": "3.1",
                "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "score": "7.4",
                "severity": "High",
                "scannerTitle": "python-ecdsa: vulnerable to the Minerva attack",
                "fixedVersion": "NONE",
            },
            "threat": {"epss": "0.012", "knownExploited": False},
            "context": {"reachability": "No path found", "fixAvailable": False},
        },
    )

    assert p.risk_scoring["source"]["score"] == "7.4"
    assert p.risk_scoring["source"]["fixedVersion"] == "NONE"
    assert p.risk_scoring["threat"]["epss"] == "0.012"


def test_source_risk_scoring_merge_preserves_reviewer_environmental_scoring():
    merged = merge_source_risk_scoring(
        {
            "source": {"score": "7.4"},
            "environmental": {
                "score": "0.0",
                "rationale": "Vulnerable ECDSA signing path is not reachable.",
                "updatedBy": "reviewer@example.com",
            },
        },
        {
            "source": {
                "source": "trivy",
                "score": "8.1",
                "fixedVersion": "0.19.3",
            },
            "context": {"fixAvailable": True},
        },
    )

    assert merged["source"]["score"] == "8.1"
    assert merged["source"]["fixedVersion"] == "0.19.3"
    assert merged["context"]["fixAvailable"] is True
    assert merged["environmental"]["score"] == "0.0"
    assert (
        merged["environmental"]["rationale"]
        == "Vulnerable ECDSA signing path is not reachable."
    )


def test_resolve_parser_infers_folder_scan_source_without_config():
    """Orphaned folder-scan keys should not fall back to SARIF."""
    assert _resolve_parser(None, "folder-scan-trivy") == "trivy"
    assert _resolve_parser(None, "folder-scan-cyclonedx") == "cyclonedx"
