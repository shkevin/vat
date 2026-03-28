"""Integration coverage for container canonicalization + alias/conflict behavior."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.api.ingest import _ingest_from_parser
from app.api.vat_data import get_vat_data
from app.schemas.auth import UserContext

pytestmark = pytest.mark.integration_db


async def _reset_container_identity_tables(db) -> None:
    await db.execute(text("TRUNCATE TABLE asset_aliases RESTART IDENTITY CASCADE"))
    await db.execute(
        text("TRUNCATE TABLE asset_digest_conflicts RESTART IDENTITY CASCADE")
    )
    await db.execute(text("TRUNCATE TABLE asset_observed_tags RESTART IDENTITY CASCADE"))
    await db.execute(text("TRUNCATE TABLE assets RESTART IDENTITY CASCADE"))
    await db.execute(text("TRUNCATE TABLE findings RESTART IDENTITY CASCADE"))
    await db.commit()


@pytest.mark.asyncio
async def test_same_repo_across_tags_single_canonical_plus_aliases(
    clean_integration_tables,
):
    db = clean_integration_tables
    await _reset_container_identity_tables(db)

    first = {
        "findings": [
            {
                "cve_id": "CVE-TAG-001",
                "severity": "High",
                "description": "first tag",
                "finding_type": "SCA",
                "component": "openssl 1.1.1",
                "image": "ghcr.io/acme/core:v1.0.0",
            }
        ]
    }
    second = {
        "findings": [
            {
                "cve_id": "CVE-TAG-002",
                "severity": "Medium",
                "description": "second tag",
                "finding_type": "SCA",
                "component": "zlib 1.2.13",
                "image": "ghcr.io/acme/core:v1.1.0",
            }
        ]
    }

    await _ingest_from_parser(db, first, "canonical", "vat-local-trivy", None)
    await _ingest_from_parser(db, second, "canonical", "vat-local-trivy", None)

    canonical = "ghcr.io/acme/core"
    images = {
        r[0]
        for r in (
            await db.execute(text("SELECT DISTINCT image FROM findings ORDER BY image ASC"))
        ).all()
    }
    assert images == {canonical}

    aliases = {
        (r[0], r[1])
        for r in (
            await db.execute(
                text(
                    "SELECT source_asset_id, canonical_asset_id FROM asset_aliases "
                    "ORDER BY source_asset_id ASC"
                )
            )
        ).all()
    }
    assert ("ghcr.io/acme/core:v1.0.0", canonical) in aliases
    assert ("ghcr.io/acme/core:v1.1.0", canonical) in aliases


@pytest.mark.asyncio
async def test_same_tag_digest_drift_sets_conflict_and_api_signal(clean_integration_tables):
    db = clean_integration_tables
    await _reset_container_identity_tables(db)

    digest_a = "sha256:" + ("a" * 64)
    digest_b = "sha256:" + ("b" * 64)
    first = {
        "findings": [
            {
                "cve_id": "CVE-DRIFT-001",
                "severity": "High",
                "description": "digest a",
                "finding_type": "SCA",
                "component": "openssl 1.1.1",
                "image": f"ghcr.io/acme/core:stable@{digest_a}",
            }
        ]
    }
    second = {
        "findings": [
            {
                "cve_id": "CVE-DRIFT-001",
                "severity": "High",
                "description": "digest b",
                "finding_type": "SCA",
                "component": "openssl 1.1.1",
                "image": f"ghcr.io/acme/core:stable@{digest_b}",
            }
        ]
    }

    await _ingest_from_parser(db, first, "canonical", "vat-local-trivy", None)
    await _ingest_from_parser(db, second, "canonical", "vat-local-trivy", None)

    conflicts = (
        await db.execute(
            text(
                "SELECT asset_id, tag, status, digests::text "
                "FROM asset_digest_conflicts ORDER BY id ASC"
            )
        )
    ).all()
    assert len(conflicts) >= 1
    assert conflicts[0][0] == "ghcr.io/acme/core"
    assert conflicts[0][1] == "stable"
    assert conflicts[0][2] == "open"
    assert "sha256:" in str(conflicts[0][3])

    payload = await get_vat_data(
        db=db,
        ctx=UserContext(
            user_id="integration",
            email="integration@vat.local",
            tenant_id=None,
            role="admin",
            raw_identity="integration",
        ),
        full=True,
        include_assets=True,
        include_zero_assets=True,
    )
    core_asset = next(a for a in payload["assets"] if a["id"] == "ghcr.io/acme/core")
    assert core_asset.get("digestConflictOpen") is True
    assert len(core_asset.get("digestConflicts") or []) >= 1


@pytest.mark.asyncio
async def test_cross_registry_same_name_does_not_auto_alias(clean_integration_tables):
    db = clean_integration_tables
    await _reset_container_identity_tables(db)

    first = {
        "findings": [
            {
                "cve_id": "CVE-REG-001",
                "severity": "High",
                "description": "ghcr",
                "finding_type": "SCA",
                "component": "libssl 3.0.0",
                "image": "ghcr.io/acme/core:latest",
            }
        ]
    }
    second = {
        "findings": [
            {
                "cve_id": "CVE-REG-002",
                "severity": "Medium",
                "description": "docker hub",
                "finding_type": "SCA",
                "component": "zlib 1.2.13",
                "image": "docker.io/acme/core:latest",
            }
        ]
    }

    await _ingest_from_parser(db, first, "canonical", "vat-local-trivy", None)
    await _ingest_from_parser(db, second, "canonical", "vat-local-trivy", None)

    images = {
        r[0]
        for r in (
            await db.execute(text("SELECT DISTINCT image FROM findings ORDER BY image ASC"))
        ).all()
    }
    assert images == {"docker.io/acme/core", "ghcr.io/acme/core"}

    aliases = {
        (r[0], r[1])
        for r in (
            await db.execute(
                text(
                    "SELECT source_asset_id, canonical_asset_id FROM asset_aliases "
                    "ORDER BY source_asset_id ASC"
                )
            )
        ).all()
    }
    assert ("ghcr.io/acme/core:latest", "ghcr.io/acme/core") in aliases
    assert ("docker.io/acme/core:latest", "docker.io/acme/core") in aliases
    assert ("docker.io/acme/core:latest", "ghcr.io/acme/core") not in aliases


@pytest.mark.asyncio
async def test_ingest_correlation_digest_flag_splits_keys_same_cve_different_manifest(
    clean_integration_tables, monkeypatch
):
    """
    With VAT_CORRELATION_INCLUDE_DIGEST off, same SCA correlation material + different
    digests → same correlation_key. With flag on → keys differ (belt-and-suspenders for Phase D).
    Uses distinct source_issue_id so replay fingerprints differ.
    """
    from app.core.config import get_settings
    from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
    from app.services.ingest import ingest_finding

    db = clean_integration_tables
    await _reset_container_identity_tables(db)

    d1 = "sha256:" + "a" * 64
    d2 = "sha256:" + "b" * 64
    cve = "CVE-FLAG-DIG-001"

    def _payload(sid: str, digest: str) -> VatFindingSchema:
        return VatFindingSchema(
            cve_id=cve,
            severity=VatSeverity.HIGH,
            description="digest flag integration",
            finding_type=VatFindingType.SCA,
            component="openssl 3.0.0",
            ecosystem="npm",
            image=f"ghcr.io/acme/digestflag:stable@{digest}",
            source_issue_id=sid,
            title=cve,
        )

    monkeypatch.delenv("VAT_CORRELATION_INCLUDE_DIGEST", raising=False)
    get_settings.cache_clear()

    f1, _ = await ingest_finding(
        db,
        _payload("iss-d1", d1),
        source_name="src-a",
        parser_id="trivy",
        auto_sync_to_tracker=False,
    )
    f2, _ = await ingest_finding(
        db,
        _payload("iss-d2", d2),
        source_name="src-b",
        parser_id="trivy",
        auto_sync_to_tracker=False,
    )
    await db.refresh(f1)
    await db.refresh(f2)
    assert f1.correlation_key == f2.correlation_key

    await _reset_container_identity_tables(db)
    monkeypatch.setenv("VAT_CORRELATION_INCLUDE_DIGEST", "true")
    get_settings.cache_clear()
    try:
        g1, _ = await ingest_finding(
            db,
            _payload("iss-g1", d1),
            source_name="src-a",
            parser_id="trivy",
            auto_sync_to_tracker=False,
        )
        g2, _ = await ingest_finding(
            db,
            _payload("iss-g2", d2),
            source_name="src-b",
            parser_id="trivy",
            auto_sync_to_tracker=False,
        )
        await db.refresh(g1)
        await db.refresh(g2)
        assert g1.correlation_key != g2.correlation_key
        assert ":digest:" in g1.correlation_key
        assert ":digest:" in g2.correlation_key
    finally:
        monkeypatch.delenv("VAT_CORRELATION_INCLUDE_DIGEST", raising=False)
        get_settings.cache_clear()
