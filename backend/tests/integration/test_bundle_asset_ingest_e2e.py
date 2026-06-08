"""Integration coverage for single-asset (bundle) ingest grouping.

A bundle scan (--asset-mode single) pushes every sub-image's findings with an
explicit X-VAT-Asset (the bundle) plus a per-image X-VAT-Source-Image. The
per-image digest must NOT be stamped on the finding: doing so makes each
sub-image a distinct container "variant" of the one bundle asset, so the asset
detail page scopes to a single image and hides the rest (asset appears empty).
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.api.ingest import _ingest_from_parser

pytestmark = pytest.mark.integration_db

_DIGEST = "sha256:" + "a" * 64


async def _reset(db) -> None:
    await db.execute(text("TRUNCATE TABLE assets RESTART IDENTITY CASCADE"))
    await db.execute(text("TRUNCATE TABLE findings RESTART IDENTITY CASCADE"))
    await db.commit()


def _payload(cve: str, comp: str) -> dict:
    return {
        "findings": [
            {
                "cve_id": cve,
                "severity": "High",
                "description": "bundle sub-image finding",
                "finding_type": "SCA",
                "component": comp,
                "image": "some-sub-image",
                "image_digest": _DIGEST,
            }
        ]
    }


@pytest.mark.asyncio
async def test_bundle_mode_drops_per_image_digest(clean_integration_tables):
    """In bundle mode the finding keys to the bundle asset with NO per-image digest."""
    db = clean_integration_tables
    await _reset(db)

    # Two different sub-images of the same bundle, each with its own digest.
    await _ingest_from_parser(
        db,
        _payload("CVE-BUNDLE-1", "openssl 1.1.1"),
        "canonical",
        "vat-local-trivy",
        None,
        asset_override="kamiwaza-bundle",
        source_image_override="image-a",
        image_digest_override=_DIGEST,
    )
    await _ingest_from_parser(
        db,
        _payload("CVE-BUNDLE-2", "zlib 1.2.13"),
        "canonical",
        "vat-local-trivy",
        None,
        asset_override="kamiwaza-bundle",
        source_image_override="image-b",
        image_digest_override="sha256:" + "b" * 64,
    )

    rows = (
        await db.execute(text("SELECT image, image_digest, tenant_id FROM findings"))
    ).all()
    assert rows, "expected ingested findings"
    for image, digest, tenant_id in rows:
        assert image == "kamiwaza-bundle", f"finding not keyed to bundle: {image}"
        assert not digest, f"per-image digest must be cleared in bundle mode, got {digest}"
        # Cross-tenant ingest (no tenant passed) must default to the bootstrap
        # tenant so findings are visible to tenant-scoped UI sessions.
        assert tenant_id == "t-default", f"expected t-default tenant, got {tenant_id}"


@pytest.mark.asyncio
async def test_non_bundle_mode_keeps_digest(clean_integration_tables):
    """Without a per-image source_image (multi-asset), the digest is preserved."""
    db = clean_integration_tables
    await _reset(db)

    await _ingest_from_parser(
        db,
        _payload("CVE-MULTI-1", "openssl 1.1.1"),
        "canonical",
        "vat-local-trivy",
        None,
        image_digest_override=_DIGEST,
    )

    rows = (await db.execute(text("SELECT image_digest FROM findings"))).all()
    assert rows
    assert any(d for (d,) in rows), "digest should be preserved outside bundle mode"
