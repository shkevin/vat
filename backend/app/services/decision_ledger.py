"""Decision ledger — record, resolve, and re-link durable triage decisions."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.tenancy import normalize_tenant_id
from app.models.decision_finding_link import DecisionFindingLink
from app.models.decision_subject_alias import DecisionSubjectAlias
from app.models.finding import Finding, Status, SuppressionScope
from app.models.triage_decision import TriageDecision
from app.models.triage_decision_revision import TriageDecisionRevision
from app.services.asset_resolver import (
    correlation_asset_image_for_ingest,
    infer_asset_kind,
)
from app.services.asset_aliases import resolve_canonical_asset_id
from app.services.audit_events import emit_audit_event, new_trace_id
from app.services.decision_subject_key import (
    DecisionSubjectCandidate,
    decision_subject_keys_for_finding,
    decision_subject_keys_for_payload,
)

# Statuses where a stored decision should auto-apply on re-import.
_AUTO_APPLY_DECISION_STATUSES = frozenset(
    {
        Status.RiskAccepted.value,
        Status.FalsePositive.value,
        Status.Suppressed.value,
        Status.NotApplicable.value,
        Status.Mitigated.value,
        Status.Duplicate.value,
        Status.Approved.value,
    }
)

_PRE_DECISION_STATUSES = frozenset(
    {
        Status.Open.value,
        Status.SyncedToTracker.value,
        Status.InReview.value,
        Status.Reopened.value,
    }
)

_RECORDABLE_STATUSES = frozenset(
    s.value
    for s in Status
    if s
    not in (
        Status.Open,
        Status.SyncedToTracker,
        Status.InReview,
        Status.Reopened,
    )
)


@dataclass
class DecisionApplyResult:
    applied: bool
    decision_id: str | None = None
    subject_key: str | None = None
    link_method: str | None = None


def _now() -> datetime:
    return datetime.utcnow()


def _tenant_key(tenant_id: str | None) -> str:
    return normalize_tenant_id(tenant_id)


def _new_decision_id() -> str:
    return f"td-{uuid.uuid4().hex[:16]}"


def _new_revision_id() -> str:
    return f"tdr-{uuid.uuid4().hex[:16]}"


def _decision_snapshot(decision: TriageDecision) -> dict[str, Any]:
    return {
        "status": decision.status,
        "suppression_scope": decision.suppression_scope,
        "justification": decision.justification,
        "compensating_controls": decision.compensating_controls,
        "reviewer_note": decision.reviewer_note,
        "attestation": decision.attestation,
        "subject_key": decision.subject_key,
        "decision_version": decision.decision_version,
    }


async def _canonical_asset_for_finding(
    db: AsyncSession, finding: Finding, *, parser_id: str | None = None
) -> str:
    raw = (finding.image or finding.component or "").strip()
    if not raw:
        return ""
    kind = infer_asset_kind(raw, parser_id or "")
    if kind == "container":
        return await correlation_asset_image_for_ingest(
            db, image=raw, parser_id=parser_id
        )
    return await resolve_canonical_asset_id(db, raw)


def _source_link_fields(finding: Finding) -> tuple[str | None, str | None]:
    for link in finding.external_links or []:
        if isinstance(link, dict) and link.get("kind") == "source":
            return (
                str(link.get("adapter_key") or "").strip() or None,
                str(link.get("issue_id") or "").strip() or None,
            )
    return None, None


async def _candidates_for_finding(
    db: AsyncSession, finding: Finding, *, parser_id: str | None = None
) -> list[DecisionSubjectCandidate]:
    canonical = await _canonical_asset_for_finding(db, finding, parser_id=parser_id)
    source_name, source_issue_id = _source_link_fields(finding)
    return decision_subject_keys_for_finding(
        finding,
        canonical_asset=canonical,
        source_name=source_name,
        source_issue_id=source_issue_id,
    )


async def lookup_decision(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    candidates: list[DecisionSubjectCandidate],
) -> tuple[TriageDecision | None, DecisionSubjectCandidate | None]:
    tenant = _tenant_key(tenant_id)
    for candidate in candidates:
        row = await db.scalar(
            select(TriageDecision).where(
                TriageDecision.tenant_id == tenant,
                TriageDecision.subject_key == candidate.subject_key,
            )
        )
        if row:
            return row, candidate

        alias = await db.get(
            DecisionSubjectAlias, {"tenant_id": tenant, "alias_key": candidate.subject_key}
        )
        if alias:
            row = await db.scalar(
                select(TriageDecision).where(
                    TriageDecision.tenant_id == tenant,
                    TriageDecision.subject_key == alias.canonical_key,
                )
            )
            if row:
                return row, candidate
    return None, None


def should_apply_decision(finding: Finding, decision: TriageDecision) -> bool:
    if finding.status.value in _PRE_DECISION_STATUSES:
        return decision.status in _AUTO_APPLY_DECISION_STATUSES
    if decision.status not in _AUTO_APPLY_DECISION_STATUSES:
        return False
    # Re-apply when decision was updated after finding last reflected it.
    link_applied = getattr(finding, "_decision_applied_version", None)
    if link_applied is not None and decision.decision_version > link_applied:
        return True
    return finding.status.value != decision.status


def apply_decision_projection(finding: Finding, decision: TriageDecision) -> None:
    finding.status = Status(decision.status)
    finding.justification = decision.justification
    finding.compensating_controls = decision.compensating_controls
    finding.reviewer_note = decision.reviewer_note
    finding.attestation = decision.attestation
    if decision.suppression_scope:
        finding.suppression_scope = SuppressionScope(decision.suppression_scope)
    audit = list(finding.audit or [])
    audit.append(
        {
            "ts": _now().isoformat() + "Z",
            "user": "system",
            "action": "Decision re-linked",
            "note": f"Applied decision {decision.id} ({decision.subject_key})",
        }
    )
    finding.audit = audit


async def upsert_decision_link(
    db: AsyncSession,
    *,
    decision: TriageDecision,
    finding: Finding,
    candidate: DecisionSubjectCandidate,
    applied_version: int,
) -> DecisionFindingLink:
    row = await db.get(
        DecisionFindingLink,
        {"decision_id": decision.id, "finding_id": finding.id},
    )
    if row:
        row.link_method = candidate.kind
        row.link_confidence = candidate.confidence
        row.applied_decision_version = applied_version
        row.linked_at = _now()
        row.unlinked_at = None
        return row

    row = DecisionFindingLink(
        decision_id=decision.id,
        finding_id=finding.id,
        link_method=candidate.kind,
        link_confidence=candidate.confidence,
        applied_decision_version=applied_version,
        linked_at=_now(),
    )
    db.add(row)
    return row


async def resolve_and_apply_decision(
    db: AsyncSession,
    finding: Finding,
    *,
    trace_id: str | None = None,
    parser_id: str | None = None,
) -> DecisionApplyResult:
    if not get_settings().decision_ledger_enabled:
        return DecisionApplyResult(applied=False)

    candidates = await _candidates_for_finding(db, finding, parser_id=parser_id)
    decision, matched = await lookup_decision(
        db, tenant_id=finding.tenant_id, candidates=candidates
    )
    if not decision or not matched:
        return DecisionApplyResult(applied=False)

    applied = False
    if should_apply_decision(finding, decision):
        apply_decision_projection(finding, decision)
        applied = True

    await upsert_decision_link(
        db,
        decision=decision,
        finding=finding,
        candidate=matched,
        applied_version=decision.decision_version if applied else 0,
    )
    decision.last_finding_id = finding.id
    decision.last_applied_at = _now()

    await emit_audit_event(
        db,
        trace_id=trace_id or new_trace_id(),
        event_type="decision.relinked",
        actor_type="system",
        finding_id=finding.id,
        decision_name="decision_relink",
        decision_reason_code=matched.kind,
        decision_confidence=matched.confidence,
        decision_result=decision.status,
        data={
            "decision_id": decision.id,
            "subject_key": decision.subject_key,
            "applied": applied,
        },
    )
    return DecisionApplyResult(
        applied=applied,
        decision_id=decision.id,
        subject_key=decision.subject_key,
        link_method=matched.kind,
    )


async def record_decision_from_finding(
    db: AsyncSession,
    finding: Finding,
    *,
    user: str,
    reason: str = "reviewer_update",
    parser_id: str | None = None,
) -> TriageDecision | None:
    """Persist reviewer decision to the ledger (dual-write from findings API)."""
    if not get_settings().decision_ledger_enabled:
        return None
    if finding.status.value not in _RECORDABLE_STATUSES:
        return None
    if not (
        finding.justification
        or finding.compensating_controls
        or finding.reviewer_note
        or finding.attestation
        or finding.status.value
        in (
            Status.RiskAccepted.value,
            Status.FalsePositive.value,
            Status.Suppressed.value,
            Status.NotApplicable.value,
        )
    ):
        return None

    candidates = await _candidates_for_finding(db, finding, parser_id=parser_id)
    if not candidates:
        return None
    primary = candidates[0]
    tenant = _tenant_key(finding.tenant_id)

    decision = await db.scalar(
        select(TriageDecision).where(
            TriageDecision.tenant_id == tenant,
            TriageDecision.subject_key == primary.subject_key,
        )
    )
    now = _now()
    ft = getattr(finding.finding_type, "value", str(finding.finding_type))

    if decision:
        decision.status = finding.status.value
        decision.suppression_scope = (
            finding.suppression_scope.value if finding.suppression_scope else None
        )
        decision.justification = finding.justification
        decision.compensating_controls = finding.compensating_controls
        decision.reviewer_note = finding.reviewer_note
        decision.attestation = finding.attestation
        decision.decision_version = (decision.decision_version or 0) + 1
        decision.updated_by = user
        decision.updated_at = now
        decision.last_finding_id = finding.id
    else:
        decision = TriageDecision(
            id=_new_decision_id(),
            tenant_id=tenant,
            subject_key=primary.subject_key,
            subject_confidence=primary.confidence,
            finding_type=ft,
            status=finding.status.value,
            suppression_scope=(
                finding.suppression_scope.value if finding.suppression_scope else None
            ),
            justification=finding.justification,
            compensating_controls=finding.compensating_controls,
            reviewer_note=finding.reviewer_note,
            attestation=finding.attestation,
            decision_version=1,
            created_by=user,
            created_at=now,
            updated_by=user,
            updated_at=now,
            last_finding_id=finding.id,
        )
        db.add(decision)

    revision = TriageDecisionRevision(
        id=_new_revision_id(),
        decision_id=decision.id,
        revision=decision.decision_version,
        snapshot=_decision_snapshot(decision),
        actor_id=user,
        reason=reason,
        created_at=now,
    )
    db.add(revision)

    await upsert_decision_link(
        db,
        decision=decision,
        finding=finding,
        candidate=primary,
        applied_version=decision.decision_version,
    )

    # Register source-issue alias when present so re-import via different path still resolves.
    for candidate in candidates[1:]:
        if candidate.kind == "source_issue":
            existing_alias = await db.get(
                DecisionSubjectAlias,
                {"tenant_id": tenant, "alias_key": candidate.subject_key},
            )
            if not existing_alias:
                db.add(
                    DecisionSubjectAlias(
                        tenant_id=tenant,
                        alias_key=candidate.subject_key,
                        canonical_key=primary.subject_key,
                        reason="source_issue",
                        created_at=now,
                    )
                )

    await emit_audit_event(
        db,
        trace_id=new_trace_id(),
        event_type="decision.recorded",
        actor_type="user",
        actor_id=user,
        finding_id=finding.id,
        decision_name="triage_decision",
        decision_reason_code=reason,
        decision_confidence=primary.confidence,
        decision_result=decision.status,
        data={
            "decision_id": decision.id,
            "subject_key": decision.subject_key,
            "decision_version": decision.decision_version,
        },
    )
    return decision


async def soft_unlink_findings(db: AsyncSession, finding_ids: list[str]) -> int:
    """Mark decision links stale when findings are deleted. Decisions are kept."""
    if not finding_ids or not get_settings().decision_ledger_enabled:
        return 0
    now = _now()
    result = await db.execute(
        update(DecisionFindingLink)
        .where(
            DecisionFindingLink.finding_id.in_(finding_ids),
            DecisionFindingLink.unlinked_at.is_(None),
        )
        .values(unlinked_at=now)
    )
    return int(result.rowcount or 0)


async def register_subject_alias(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    alias_key: str,
    canonical_key: str,
    reason: str,
) -> None:
    if not get_settings().decision_ledger_enabled:
        return
    tenant = _tenant_key(tenant_id)
    existing = await db.get(
        DecisionSubjectAlias, {"tenant_id": tenant, "alias_key": alias_key}
    )
    if existing:
        existing.canonical_key = canonical_key
        existing.reason = reason
        return
    db.add(
        DecisionSubjectAlias(
            tenant_id=tenant,
            alias_key=alias_key,
            canonical_key=canonical_key,
            reason=reason,
            created_at=_now(),
        )
    )


async def candidates_for_payload(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    payload: object,
    source_name: str,
    parser_id: str | None = None,
) -> list[DecisionSubjectCandidate]:
    """DSK candidates at ingest time (uses canonical asset resolution)."""
    image = getattr(payload, "image", None) or ""
    component = getattr(payload, "component", None) or ""
    raw_asset = (image or component or "").strip()
    if raw_asset:
        kind = infer_asset_kind(raw_asset, parser_id or "")
        if kind == "container":
            canonical = await correlation_asset_image_for_ingest(
                db, image=raw_asset, parser_id=parser_id
            )
        else:
            canonical = await resolve_canonical_asset_id(db, raw_asset)
    else:
        canonical = ""

    return decision_subject_keys_for_payload(
        tenant_id=tenant_id,
        finding_type=str(getattr(getattr(payload, "finding_type", None), "value", "")),
        canonical_asset=canonical,
        branch=getattr(payload, "branch", None) or "",
        tag=getattr(payload, "tag", None) or "",
        cve_id=getattr(payload, "cve_id", None) or "",
        component=getattr(payload, "component", None) or "",
        ecosystem=getattr(payload, "ecosystem", None),
        rule_id=getattr(payload, "rule_id", None),
        file_path=getattr(payload, "file_path", None),
        benchmark_family=getattr(payload, "benchmark_family", None),
        license_expression=getattr(payload, "license_expression", None),
        stable_rule_key=getattr(payload, "stable_rule_key", None),
        profile_scope=getattr(payload, "profile_scope", None),
        source_name=source_name,
        source_issue_id=getattr(payload, "source_issue_id", None),
    )
