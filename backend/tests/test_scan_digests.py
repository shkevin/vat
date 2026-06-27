"""Known-digest projection (Phase 0, event-driven scanning).

Shared test DB without per-test rollback, so we use sentinel digests and scope
assertions to them (the table may hold rows from other tests/fixtures).
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete

from app.core.ingest_auth import get_ingest_source
from app.main import app
from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding, FindingType, Severity, Status
from app.services.scan_digests import known_image_digests

# Distinct 64-hex sentinels; A-variant stored mixed-case to exercise normalization.
DIGEST_A = "sha256:" + "a" * 64
DIGEST_A_MIXED = "SHA256:" + "A" * 64  # normalizes to DIGEST_A
DIGEST_B = "sha256:" + "b" * 64
SENTINELS = {DIGEST_A, DIGEST_B}


def _finding(fid: str, digest: str | None) -> Finding:
    return Finding(
        id=fid,
        finding_type=FindingType.SCA,
        fingerprint_id=f"fp-{fid}",
        cve_id="CVE-2026-0001",
        severity=Severity.High,
        status=Status.Open,
        image_digest=digest,
        audit=[],
        tracker_comment=False,
        archived=False,
        external_links=[],
        regression_count=0,
    )


@pytest.mark.integration_db
async def test_known_image_digests_dedups_normalizes_across_tables(db) -> None:
    fids = ["scan-dig-f1", "scan-dig-f2", "scan-dig-f3"]
    tag_assets = ["scan-dig-asset"]
    await db.execute(delete(Finding).where(Finding.id.in_(fids)))
    await db.execute(delete(AssetObservedTag).where(AssetObservedTag.asset_id.in_(tag_assets)))
    await db.commit()

    # A appears in findings (mixed-case) AND observed tags (lowercase) -> 1 entry.
    db.add(_finding("scan-dig-f1", DIGEST_A_MIXED))
    db.add(_finding("scan-dig-f2", DIGEST_B))  # B only in findings
    db.add(_finding("scan-dig-f3", None))  # NULL excluded
    db.add(
        AssetObservedTag(
            asset_id="scan-dig-asset", tag="latest", observation_count=1, last_digest=DIGEST_A
        )
    )
    db.add(
        AssetObservedTag(
            asset_id="scan-dig-asset", tag="prev", observation_count=1, last_digest=None
        )
    )
    await db.commit()

    result = await known_image_digests(db)

    assert [d for d in result if d in SENTINELS] == sorted(SENTINELS)  # deduped + sorted
    assert all(d.startswith("sha256:") and d.islower() for d in result)  # normalized

    await db.execute(delete(Finding).where(Finding.id.in_(fids)))
    await db.execute(delete(AssetObservedTag).where(AssetObservedTag.asset_id.in_(tag_assets)))
    await db.commit()


@pytest.mark.integration_db
async def test_known_digests_endpoint_etag_304(client) -> None:
    app.dependency_overrides[get_ingest_source] = lambda: ("operator", "test")
    try:
        r1 = await client.get("/api/scan/known-digests")
        assert r1.status_code == 200
        assert isinstance(r1.json()["digests"], list)
        etag = r1.headers["etag"]

        r2 = await client.get("/api/scan/known-digests", headers={"If-None-Match": etag})
        assert r2.status_code == 304
        assert r2.headers["etag"] == etag
    finally:
        app.dependency_overrides.pop(get_ingest_source, None)
