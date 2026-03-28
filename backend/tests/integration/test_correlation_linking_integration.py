"""
Integration tests for correlation linking (ORM + ingest). See ``test_correlation_ingest_e2e.py``
for full parser + HTTP-path parity with vat-local-scanner source names.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.api.assets import AssetGroupRequest, group_asset_into_target
from app.models.asset import Asset
from app.models.asset_merge_review import AssetMergeReview
from app.models.finding import Finding, FindingType, Severity, Status
from app.schemas.auth import UserContext
from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity
from app.services.correlation_linking import apply_correlation_linking
from app.services.ingest import ingest_finding

pytestmark = pytest.mark.integration_db


def _unique_cve() -> str:
    return f"CVE-INT-{uuid.uuid4().hex[:12]}"


def _sca_payload(cve: str) -> VatFindingSchema:
    return VatFindingSchema(
        cve_id=cve,
        severity=VatSeverity.HIGH,
        description="integration correlation test",
        finding_type=VatFindingType.SCA,
        image="registry.example/corr-test",
        branch="main",
        tag="v1",
        component="openssl 3.0.0",
        ecosystem="npm",
        title=cve,
    )


@pytest.mark.asyncio
async def test_ingest_two_sources_same_tenant_links_second_to_first(
    clean_integration_tables,
):
    """Different replay fingerprints, same correlation_key + tenant → second.correlated_to == first."""
    db = clean_integration_tables
    cve = _unique_cve()
    p = _sca_payload(cve)
    tenant = f"t-int-{uuid.uuid4().hex[:8]}"

    f1, new1 = await ingest_finding(
        db,
        p,
        source_name="corr-src-a",
        tenant_id=tenant,
        trace_id=f"tr-{uuid.uuid4().hex}",
        parser_id="trivy",
        auto_sync_to_tracker=False,
    )
    assert new1 is True
    await db.refresh(f1)

    f2, new2 = await ingest_finding(
        db,
        p,
        source_name="corr-src-b",
        tenant_id=tenant,
        trace_id=f"tr-{uuid.uuid4().hex}",
        parser_id="grype",
        auto_sync_to_tracker=False,
    )
    assert new2 is True
    await db.refresh(f1)
    await db.refresh(f2)

    assert f1.correlated_to is None
    assert f2.correlated_to == f1.id
    assert f1.correlation_key == f2.correlation_key


@pytest.mark.asyncio
async def test_same_correlation_key_different_tenants_never_cross_link(
    clean_integration_tables,
):
    """Tenant A and B can share the same correlation_key string; clusters are isolated."""
    db = clean_integration_tables
    cve = _unique_cve()
    p = _sca_payload(cve)
    ta = f"t-a-{uuid.uuid4().hex[:8]}"
    tb = f"t-b-{uuid.uuid4().hex[:8]}"

    fa, _ = await ingest_finding(
        db,
        p,
        source_name="corr-src-x",
        tenant_id=ta,
        trace_id=f"tr-{uuid.uuid4().hex}",
        parser_id="trivy",
        auto_sync_to_tracker=False,
    )
    fb, _ = await ingest_finding(
        db,
        p,
        source_name="corr-src-y",
        tenant_id=tb,
        trace_id=f"tr-{uuid.uuid4().hex}",
        parser_id="grype",
        auto_sync_to_tracker=False,
    )
    await db.refresh(fa)
    await db.refresh(fb)

    assert fa.correlated_to is None
    assert fb.correlated_to is None
    assert fa.correlation_key == fb.correlation_key
    assert fa.tenant_id != fb.tenant_id


@pytest.mark.asyncio
async def test_three_findings_repair_non_canonical_pointers(clean_integration_tables):
    """Oldest row is canonical; later rows + stale pointers are normalized to canonical."""
    db = clean_integration_tables
    key = f"v1:sca:repair:{uuid.uuid4().hex}"
    fp1 = "a" * 64
    fp2 = "b" * 64
    fp3 = "c" * 64
    cve = _unique_cve()

    f1 = Finding(
        id=f"f-repair-1-{uuid.uuid4().hex[:6]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp1,
        cve_id=cve,
        severity=Severity.High,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="high",
        correlated_to=None,
        tenant_id=None,
        source="test",
    )
    f2 = Finding(
        id=f"f-repair-2-{uuid.uuid4().hex[:6]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp2,
        cve_id=cve,
        severity=Severity.High,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="high",
        correlated_to="stale-wrong-id",
        tenant_id=None,
        source="test",
    )
    f3 = Finding(
        id=f"f-repair-3-{uuid.uuid4().hex[:6]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp3,
        cve_id=cve,
        severity=Severity.High,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="high",
        correlated_to=None,
        tenant_id=None,
        source="test",
    )
    db.add_all([f1, f2, f3])
    await db.commit()
    for f in (f1, f2, f3):
        await db.refresh(f)

    await apply_correlation_linking(db, f3, "trace-repair", parser_id="test")
    await db.commit()

    await db.refresh(f1)
    await db.refresh(f2)
    await db.refresh(f3)

    rows = (
        (
            await db.execute(
                select(Finding)
                .where(Finding.correlation_key == key)
                .order_by(Finding.created_at.asc(), Finding.id.asc())
            )
        )
        .scalars()
        .all()
    )
    root = rows[0]
    assert root.correlated_to is None
    for r in rows[1:]:
        assert r.correlated_to == root.id


@pytest.mark.asyncio
async def test_cluster_membership_mismatch_skips_without_mutation(
    clean_integration_tables,
):
    """If the subject row is not returned by the cluster query, do not link anyone."""
    db = clean_integration_tables
    key = f"v1:sca:mismatch:{uuid.uuid4().hex}"
    fp = "d" * 64
    cve = _unique_cve()

    orphan = Finding(
        id=f"f-orphan-{uuid.uuid4().hex[:8]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp,
        cve_id=cve,
        severity=Severity.High,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="high",
        correlated_to=None,
        tenant_id="tenant-x",
        source="test",
    )
    db.add(orphan)
    await db.commit()
    await db.refresh(orphan)

    stale = SimpleNamespace(
        id=orphan.id,
        correlation_key=key,
        correlation_confidence="high",
        tenant_id=None,
    )

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, stale, "tr-mismatch", parser_id="test")
        await db.commit()

    reasons = [c.kwargs.get("decision_reason_code") for c in emit.await_args_list]
    assert "cluster_membership_mismatch" in reasons
    await db.refresh(orphan)
    assert orphan.correlated_to is None


@pytest.mark.asyncio
async def test_medium_score_links_without_review_queue(clean_integration_tables):
    """Medium tier should auto-link deterministically and avoid review queue."""
    db = clean_integration_tables
    key = f"sast:medium:{uuid.uuid4().hex}"

    f1 = Finding(
        id=f"f-med-1-{uuid.uuid4().hex[:6]}",
        finding_type=FindingType.SAST,
        fingerprint_id="m" * 64,
        cve_id="",
        severity=Severity.Medium,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="medium",
        correlated_to=None,
        image="repo/app",
        branch="main",
        tag="v1",
        tenant_id=None,
        source="test",
    )
    f2 = Finding(
        id=f"f-med-2-{uuid.uuid4().hex[:6]}",
        finding_type=FindingType.SAST,
        fingerprint_id="n" * 64,
        cve_id="",
        severity=Severity.Medium,
        status=Status.Open,
        correlation_key=key,
        correlation_confidence="medium",
        correlated_to=None,
        image="repo/app",
        branch="main",
        tag="v1",
        tenant_id=None,
        source="test",
    )
    db.add_all([f1, f2])
    await db.commit()
    await db.refresh(f1)
    await db.refresh(f2)

    await apply_correlation_linking(
        db, f2, f"trace-{uuid.uuid4().hex}", parser_id="test"
    )
    await db.commit()
    await db.refresh(f1)
    await db.refresh(f2)

    assert f2.correlated_to == f1.id


@pytest.mark.asyncio
async def test_manual_merge_runs_postpass_for_moved_findings_only(
    clean_integration_tables,
):
    """Manual asset merge should run the same linker policy for moved findings."""
    db = clean_integration_tables
    src_asset = f"asset-src-{uuid.uuid4().hex[:6]}"
    dst_asset = f"asset-dst-{uuid.uuid4().hex[:6]}"

    db.add_all(
        [
            Asset(id=src_asset, name=src_asset, type="repo", source="test"),
            Asset(id=dst_asset, name=dst_asset, type="repo", source="test"),
            AssetMergeReview(
                source_asset_id=src_asset,
                target_asset_id=dst_asset,
                status="approved",
                note="approved in integration test",
                strategy="manual",
                score=1.0,
                confidence="high",
                details={},
                created_by="reviewer@vat.local",
                updated_by="reviewer@vat.local",
            ),
            Finding(
                id=f"f-mrg-target-{uuid.uuid4().hex[:6]}",
                finding_type=FindingType.SCA,
                fingerprint_id=f"fp-target-{uuid.uuid4().hex}",
                cve_id="",
                severity=Severity.High,
                status=Status.Open,
                image=dst_asset,
                branch="main",
                tag=dst_asset,
                component_base="pkg-target",
                component="pkg target",
                source="Aikido",
                correlation_key="v1:sca:merge-int:key",
                correlation_confidence="medium",
            ),
            Finding(
                id=f"f-mrg-source-{uuid.uuid4().hex[:6]}",
                finding_type=FindingType.SCA,
                fingerprint_id=f"fp-source-{uuid.uuid4().hex}",
                cve_id="",
                severity=Severity.High,
                status=Status.Open,
                image=src_asset,
                branch="main",
                tag=src_asset,
                component_base="pkg-source",
                component="pkg source",
                source="trivy",
                correlation_key="v1:sca:merge-int:key",
                correlation_confidence="medium",
            ),
        ]
    )
    await db.commit()

    ctx = UserContext(
        user_id="admin",
        email="admin@vat.local",
        tenant_id=None,
        role="admin",
        raw_identity="admin@vat.local",
    )
    out = await group_asset_into_target(
        src_asset,
        AssetGroupRequest(target_asset_id=dst_asset, reassign_existing_findings=True),
        db=db,
        ctx=ctx,
    )
    await db.commit()
    assert out["findings_updated"] >= 1

    moved = (
        await db.execute(select(Finding).where(Finding.id.like("f-mrg-source-%")))
    ).scalar_one()
    roots = (
        (
            await db.execute(
                select(Finding)
                .where(Finding.correlation_key == "v1:sca:merge-int:key")
                .order_by(Finding.created_at.asc(), Finding.id.asc())
            )
        )
        .scalars()
        .all()
    )
    assert len(roots) == 2
    canonical = roots[0]
    assert moved.correlated_to == canonical.id
