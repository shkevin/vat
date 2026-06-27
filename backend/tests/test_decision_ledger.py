"""Integration tests for the decision ledger (re-link after delete/re-import)."""

import uuid

import pytest
from sqlalchemy import delete, select

from app.models.decision_finding_link import DecisionFindingLink
from app.models.decision_subject_alias import DecisionSubjectAlias
from app.models.finding import Finding, FindingType, Severity, Status
from app.models.triage_decision import TriageDecision
from app.models.triage_decision_revision import TriageDecisionRevision
from app.services.decision_ledger import (
    get_decision_detail,
    record_decision_from_finding,
    resolve_and_apply_decision,
    soft_unlink_findings,
)


@pytest.fixture(autouse=True)
async def _ledger_test_cleanup(db):
    """Remove test data (tenant-<uuid>) so these integration tests don't pollute the DB."""

    async def _clean():
        test_decisions = (
            select(TriageDecision.id)
            .where(TriageDecision.tenant_id.like("tenant-%"))
            .scalar_subquery()
        )
        await db.execute(
            delete(TriageDecisionRevision).where(
                TriageDecisionRevision.decision_id.in_(test_decisions)
            )
        )
        await db.execute(
            delete(DecisionFindingLink).where(
                DecisionFindingLink.decision_id.in_(test_decisions)
            )
        )
        await db.execute(
            delete(DecisionSubjectAlias).where(
                DecisionSubjectAlias.tenant_id.like("tenant-%")
            )
        )
        await db.execute(
            delete(TriageDecision).where(TriageDecision.tenant_id.like("tenant-%"))
        )
        await db.execute(delete(Finding).where(Finding.tenant_id.like("tenant-%")))
        await db.commit()

    await _clean()
    yield
    await _clean()


@pytest.mark.integration_db
async def test_decision_survives_finding_delete_and_relinks(db) -> None:
    tenant = f"tenant-{uuid.uuid4().hex[:8]}"
    asset = "decision-ledger-test:latest"

    finding = Finding(
        id=f"f-{uuid.uuid4().hex[:12]}",
        finding_type=FindingType.SCA,
        fingerprint_id=f"fp-{uuid.uuid4().hex}",
        cve_id="CVE-2024-9999",
        severity=Severity.High,
        status=Status.RiskAccepted,
        component="openssl@3.0.2",
        image=asset,
        justification="Accepted for staging only",
        attestation={
            "approver": "Alice",
            "waiverRef": "WAV-TEST-1",
            "expiresAt": "2099-01-01",
        },
        tenant_id=tenant,
        sources=[],
        audit=[],
    )
    db.add(finding)
    await db.flush()

    decision = await record_decision_from_finding(
        db, finding, user="reviewer@test.com", reason="test"
    )
    assert decision is not None
    # subject_key is derived from the finding (canonical asset + ecosystem), so we
    # assert it exists; the re-link assertions below prove record/resolve agree on it.
    assert decision.subject_key
    await db.commit()

    finding_id = finding.id
    await soft_unlink_findings(db, [finding_id])
    await db.delete(finding)
    await db.commit()

    stored = await db.scalar(
        select(TriageDecision).where(TriageDecision.id == decision.id)
    )
    assert stored is not None
    assert stored.status == Status.RiskAccepted.value

    new_finding = Finding(
        id=f"f-{uuid.uuid4().hex[:12]}",
        finding_type=FindingType.SCA,
        fingerprint_id=f"fp-{uuid.uuid4().hex}",
        cve_id="CVE-2024-9999",
        severity=Severity.High,
        status=Status.Open,
        component="openssl@3.0.2",
        image=asset,
        tenant_id=tenant,
        sources=[],
        audit=[],
    )
    db.add(new_finding)
    await db.flush()

    result = await resolve_and_apply_decision(db, new_finding)
    assert result.applied is True
    assert new_finding.status == Status.RiskAccepted
    assert new_finding.justification == "Accepted for staging only"
    assert new_finding.attestation["waiverRef"] == "WAV-TEST-1"
    await db.commit()

    link = await db.scalar(
        select(DecisionFindingLink).where(
            DecisionFindingLink.decision_id == decision.id,
            DecisionFindingLink.finding_id == new_finding.id,
            DecisionFindingLink.unlinked_at.is_(None),
        )
    )
    assert link is not None


@pytest.mark.integration_db
async def test_resolve_is_idempotent(db) -> None:
    tenant = f"tenant-{uuid.uuid4().hex[:8]}"
    finding = Finding(
        id=f"f-{uuid.uuid4().hex[:12]}",
        finding_type=FindingType.SCA,
        fingerprint_id=f"fp-{uuid.uuid4().hex}",
        cve_id="CVE-2024-8888",
        severity=Severity.Medium,
        status=Status.FalsePositive,
        component="lodash@4.17.21",
        image="idempotent-img:latest",
        justification="Scanner rule misfire",
        tenant_id=tenant,
        sources=[],
        audit=[],
    )
    db.add(finding)
    await db.flush()
    await record_decision_from_finding(db, finding, user="reviewer@test.com")
    await db.commit()

    finding.status = Status.Open
    finding.justification = None
    await db.flush()

    r1 = await resolve_and_apply_decision(db, finding)
    r2 = await resolve_and_apply_decision(db, finding)
    assert r1.applied is True
    assert r2.applied is False
    assert finding.status == Status.FalsePositive


@pytest.mark.integration_db
async def test_decision_detail_drilldown(db) -> None:
    """Auditor drill-down returns the decision + full revision history + live links."""
    tenant = f"tenant-{uuid.uuid4().hex[:8]}"
    finding = Finding(
        id=f"f-{uuid.uuid4().hex[:12]}",
        finding_type=FindingType.SCA,
        fingerprint_id=f"fp-{uuid.uuid4().hex}",
        cve_id="CVE-2024-3333",
        severity=Severity.High,
        status=Status.RiskAccepted,
        component="openssl@3.0.2",
        image="drilldown-test:latest",
        justification="v1",
        attestation={"waiverRef": "W-DD", "expiresAt": "2099-01-01"},
        tenant_id=tenant,
        sources=[],
        audit=[],
    )
    db.add(finding)
    await db.flush()
    decision = await record_decision_from_finding(
        db, finding, user="rev@test", reason="create"
    )
    finding.justification = "v2"
    await db.flush()
    await record_decision_from_finding(
        db, finding, user="rev2@test", reason="reviewer_update"
    )
    await db.commit()

    detail = await get_decision_detail(
        db, tenant_id=tenant, cross_tenant=False, decision_id=decision.id
    )
    assert detail is not None
    assert detail["decision_version"] == 2
    assert [r["reason"] for r in detail["revisions"]] == ["create", "reviewer_update"]
    assert detail["linked_finding_ids"] == [finding.id]

    by_key = await get_decision_detail(
        db, tenant_id=tenant, cross_tenant=False, subject_key=decision.subject_key
    )
    assert by_key is not None and by_key["decision_id"] == decision.id

    # Tenant-scoped: a different tenant cannot drill into it.
    other = await get_decision_detail(
        db, tenant_id="tenant-other", cross_tenant=False, decision_id=decision.id
    )
    assert other is None
