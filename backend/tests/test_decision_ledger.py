"""Integration tests for the decision ledger (re-link after delete/re-import)."""

import uuid

import pytest
from sqlalchemy import select

from app.models.decision_finding_link import DecisionFindingLink
from app.models.finding import Finding, FindingType, Severity, Status
from app.models.triage_decision import TriageDecision
from app.services.decision_ledger import (
    record_decision_from_finding,
    resolve_and_apply_decision,
    soft_unlink_findings,
)
from app.services.decision_subject_key import decision_subject_keys_for_payload


@pytest.mark.integration_db
async def test_decision_survives_finding_delete_and_relinks(db) -> None:
    tenant = f"tenant-{uuid.uuid4().hex[:8]}"
    asset = "decision-ledger-test:latest"
    keys = decision_subject_keys_for_payload(
        tenant_id=tenant,
        finding_type="SCA",
        canonical_asset=asset,
        cve_id="CVE-2024-9999",
        component="openssl@3.0.2",
        ecosystem="deb",
    )
    subject_key = keys[0].subject_key

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
    assert decision.subject_key == subject_key
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
