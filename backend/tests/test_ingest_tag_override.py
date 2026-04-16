"""Regression tests for authoritative tag override in bundle ingest mode."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.sbom import SbomPackage
from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
from app.services.ingest import ingest_finding
from app.services.ingest_tag_policy import IngestTagPolicy
from app.services.sbom import backfill_derived_purls, import_sbom
from app.services.sbom import _purl_from_osv_identity


@pytest.mark.anyio
async def test_ingest_force_tag_override_updates_existing_finding_tag(db) -> None:
    """
    When a bundle ingest provides an authoritative tag (single-asset mode),
    existing findings should adopt that tag instead of preserving old values.
    """
    uniq = uuid.uuid4().hex[:8]
    source = f"trivy-bundle-{uniq}"
    payload = VatFindingSchema(
        cve_id=f"RULE-{uniq}",
        severity=VatSeverity.HIGH,
        description="tag override regression",
        finding_type=VatFindingType.SECRET,
        title="Hardcoded token",
        file_path=f"/tmp/{uniq}.env",
        line=7,
        image="vat-codebase",
        component="vat-codebase",
        tag="legacy-tag",
    )

    first, created_first = await ingest_finding(
        db,
        payload,
        source_name=source,
        parser_id="gitleaks",
        auto_sync_to_tracker=False,
    )
    assert created_first is True
    assert first.tag == "legacy-tag"

    override_payload = payload.model_copy(update={"tag": "2026-03-29_191810"})
    second, created_second = await ingest_finding(
        db,
        override_payload,
        source_name=source,
        parser_id="gitleaks",
        auto_sync_to_tracker=False,
        force_tag_override=True,
    )

    assert created_second is False
    assert second.id == first.id
    assert second.tag == "2026-03-29_191810"


@pytest.mark.anyio
async def test_import_sbom_force_tag_override_updates_license_finding_tag(db) -> None:
    """SBOM-created license findings should inherit authoritative scan tag."""
    uniq = uuid.uuid4().hex[:8]
    package_name = f"pkg-{uniq}"
    component = f"vat-codebase-{uniq}"
    doc = {
        "components": [
            {
                "name": package_name,
                "version": "1.0.0",
                "licenses": [{"license": {"id": "GPL-3.0"}}],
            }
        ]
    }

    await import_sbom(
        db,
        doc,
        source="trivy",
        component=component,
        finding_tag="legacy-tag",
    )
    first = (
        await db.execute(
            select(Finding).where(
                Finding.cve_id == f"LICENSE-GPL-3.0-{package_name}",
                Finding.image == component,
                Finding.component == package_name,
            )
        )
    ).scalar_one()
    assert first.tag == "legacy-tag"

    await import_sbom(
        db,
        doc,
        source="trivy",
        component=component,
        finding_tag="2026-03-29_194016",
        force_finding_tag_override=True,
    )
    updated = (
        await db.execute(
            select(Finding).where(
                Finding.cve_id == f"LICENSE-GPL-3.0-{package_name}",
                Finding.image == component,
                Finding.component == package_name,
            )
        )
    ).scalar_one()
    assert updated.id == first.id
    assert updated.tag == "2026-03-29_194016"


@pytest.mark.anyio
async def test_normalize_asset_findings_tag_updates_legacy_rows(db) -> None:
    """Single-asset mode should normalize legacy tags for same source+asset."""
    uniq = uuid.uuid4().hex[:8]
    source = f"trivy-{uniq}"
    payload = VatFindingSchema(
        cve_id=f"RULE-{uniq}",
        severity=VatSeverity.HIGH,
        description="legacy tag normalization",
        finding_type=VatFindingType.SCA,
        title="dependency vuln",
        image="vat-codebase",
        component="package-a 1.0.0",
        tag="vat-codebase",
    )
    finding, _ = await ingest_finding(
        db,
        payload,
        source_name=source,
        parser_id="trivy",
        auto_sync_to_tracker=False,
    )
    assert finding.tag == "vat-codebase"

    policy = IngestTagPolicy.from_headers(
        asset_override="vat-codebase",
        tag_override="2026-03-30_111634",
    )
    updated_count = await policy.normalize_existing_source_asset_tags(
        db,
        source_name=source,
        asset_id="vat-codebase",
    )
    await db.commit()
    assert updated_count >= 1

    refreshed = (
        await db.execute(select(Finding).where(Finding.id == finding.id))
    ).scalar_one()
    assert refreshed.tag == "2026-03-30_111634"


@pytest.mark.anyio
async def test_import_sbom_extracts_purl_from_component_fields(db) -> None:
    uniq = uuid.uuid4().hex[:8]
    component = f"vat-codebase-{uniq}"
    doc = {
        "components": [
            {
                "name": f"pkg-a-{uniq}",
                "version": "1.0.0",
                "purl": f"pkg:pypi/pkg-a-{uniq}@1.0.0",
            },
            {
                "name": f"pkg-b-{uniq}",
                "version": "2.0.0",
                "bom-ref": f"pkg:golang/github.com/example/pkg-b-{uniq}@v2.0.0",
            },
        ]
    }

    created, _updated = await import_sbom(
        db,
        doc,
        source="Aikido",
        component=component,
    )
    assert created >= 2

    rows = (
        await db.execute(
            select(SbomPackage.name, SbomPackage.purl)
            .where(SbomPackage.component == component)
            .order_by(SbomPackage.name.asc())
        )
    ).all()
    by_name = {name: purl for name, purl in rows}
    assert by_name[f"pkg-a-{uniq}"] == f"pkg:pypi/pkg-a-{uniq}@1.0.0"
    assert (
        by_name[f"pkg-b-{uniq}"]
        == f"pkg:golang/github.com/example/pkg-b-{uniq}@v2.0.0"
    )


@pytest.mark.anyio
async def test_import_sbom_derives_purl_when_missing(db) -> None:
    uniq = uuid.uuid4().hex[:8]
    component = f"vat-codebase-{uniq}"
    doc = {
        "components": [
            {
                "name": f"github.com/example/pkg-{uniq}",
                "version": "v1.2.3",
            }
        ]
    }
    await import_sbom(db, doc, source="Aikido", component=component)
    row = (
        await db.execute(
            select(SbomPackage).where(
                SbomPackage.component == component,
                SbomPackage.name == f"github.com/example/pkg-{uniq}",
            )
        )
    ).scalar_one()
    assert row.purl == f"pkg:golang/github.com/example/pkg-{uniq}@v1.2.3"
    assert row.purl_source == "derived"
    assert row.purl_confidence == "high"


@pytest.mark.anyio
async def test_backfill_derived_purls_updates_missing_rows(db) -> None:
    uniq = uuid.uuid4().hex[:8]
    component = f"vat-codebase-{uniq}"
    sp = SbomPackage(
        id=f"sbom-{uniq}",
        name=f"ca-certificates-bundle-{uniq}",
        version="20251003-r4",
        component=component,
        language=None,
        purl=None,
        sources=[{"name": "Aikido", "importedAt": "2026-04-02T00:00:00Z"}],
    )
    db.add(sp)
    await db.commit()

    result = await backfill_derived_purls(db, only_source="aikido")
    assert result["updated"] >= 1

    refreshed = (
        await db.execute(select(SbomPackage).where(SbomPackage.id == f"sbom-{uniq}"))
    ).scalar_one()
    assert refreshed.purl == f"pkg:apk/alpine/ca-certificates-bundle-{uniq}@20251003-r4"
    assert refreshed.purl_source == "derived"


def test_purl_from_osv_identity_builds_expected_values() -> None:
    assert (
        _purl_from_osv_identity(
            name="requests",
            version="2.31.0",
            ecosystem="PyPI",
        )
        == "pkg:pypi/requests@2.31.0"
    )
    assert (
        _purl_from_osv_identity(
            name="@types/node",
            version="20.12.7",
            ecosystem="npm",
        )
        == "pkg:npm/%40types/node@20.12.7"
    )
    assert (
        _purl_from_osv_identity(
            name="anyhow",
            version="1.0.102",
            ecosystem="crates.io",
        )
        == "pkg:cargo/anyhow@1.0.102"
    )
