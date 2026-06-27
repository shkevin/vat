"""Decision ledger — record, resolve, and re-link durable triage decisions."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
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
        "identity_snapshot": decision.identity_snapshot,
        "subject_key": decision.subject_key,
        "decision_version": decision.decision_version,
    }


def _identity_snapshot_from_finding(finding: Finding) -> dict[str, Any]:
    ft = getattr(finding.finding_type, "value", str(finding.finding_type))
    sev = getattr(finding.severity, "value", str(finding.severity))
    return {
        "cveId": finding.cve_id,
        "title": finding.title,
        "severity": sev,
        "component": finding.component,
        "image": finding.image,
        "findingType": ft,
        "controlRef": finding.control_ref,
        "ruleId": finding.rule_id,
    }


def _exp_date_str(expires_at: object) -> str | None:
    if not expires_at:
        return None
    text = str(expires_at).strip()
    return text[:10] if len(text) >= 10 else text or None


def _is_waiver_expired(expires_at: object, *, today: str) -> bool:
    exp_date = _exp_date_str(expires_at)
    return bool(exp_date and exp_date < today)


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

    # Surface the link's last-applied version so should_apply_decision can
    # re-project a decision that was edited after the finding last reflected it.
    existing_link = await db.get(
        DecisionFindingLink,
        {"decision_id": decision.id, "finding_id": finding.id},
    )
    finding._decision_applied_version = (
        existing_link.applied_decision_version if existing_link else None
    )

    applied = False
    if should_apply_decision(finding, decision):
        apply_decision_projection(finding, decision)
        applied = True

    await upsert_decision_link(
        db,
        decision=decision,
        finding=finding,
        candidate=matched,
        applied_version=(
            decision.decision_version
            if applied
            else (existing_link.applied_decision_version if existing_link else 0)
        ),
    )
    decision.last_finding_id = finding.id
    decision.last_applied_at = _now()

    # Audit only real changes / first link; no-op re-imports would flood the ledger.
    if applied or existing_link is None:
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
        decision.identity_snapshot = _identity_snapshot_from_finding(finding)
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
            identity_snapshot=_identity_snapshot_from_finding(finding),
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


def _waiver_matches_asset(record: dict[str, Any], asset_id: str) -> bool:
    needle = (asset_id or "").strip()
    if not needle:
        return True
    for key in ("image", "component", "componentBase"):
        val = str(record.get(key) or "").strip()
        if val == needle:
            return True
    return False


def _waiver_record_from_decision(
    decision: TriageDecision,
    *,
    finding: Finding | None,
    finding_id: str | None,
    linked: bool,
) -> dict[str, Any]:
    snap = decision.identity_snapshot if isinstance(decision.identity_snapshot, dict) else {}
    att = decision.attestation if isinstance(decision.attestation, dict) else {}

    if finding is not None:
        ft = getattr(finding.finding_type, "value", str(finding.finding_type))
        sev = getattr(finding.severity, "value", str(finding.severity))
        return {
            "decisionId": decision.id,
            "subjectKey": decision.subject_key,
            "tenantId": decision.tenant_id,
            "findingId": finding.id,
            "linked": linked,
            "findingType": ft,
            "status": decision.status,
            "cveId": finding.cve_id,
            "title": finding.title,
            "severity": sev,
            "component": finding.component,
            "image": finding.image,
            "ruleId": finding.rule_id,
            "controlRef": finding.control_ref,
            "attestation": att,
            "justification": decision.justification,
            "decisionVersion": decision.decision_version,
            "updatedAt": decision.updated_at.isoformat() if decision.updated_at else None,
        }

    return {
        "decisionId": decision.id,
        "subjectKey": decision.subject_key,
        "tenantId": decision.tenant_id,
        "findingId": finding_id,
        "linked": linked,
        "findingType": snap.get("findingType") or decision.finding_type,
        "status": decision.status,
        "cveId": snap.get("cveId") or "",
        "title": snap.get("title"),
        "severity": snap.get("severity"),
        "component": snap.get("component"),
        "image": snap.get("image"),
        "ruleId": snap.get("ruleId"),
        "controlRef": snap.get("controlRef"),
        "attestation": att,
        "justification": decision.justification,
        "decisionVersion": decision.decision_version,
        "updatedAt": decision.updated_at.isoformat() if decision.updated_at else None,
    }


async def list_waiver_decisions(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    cross_tenant: bool = False,
    asset_id: str | None = None,
) -> list[dict[str, Any]]:
    """List Risk Accepted ledger decisions (survives finding deletion)."""
    if not get_settings().decision_ledger_enabled:
        return []

    q = select(TriageDecision).where(
        TriageDecision.status == Status.RiskAccepted.value,
        TriageDecision.attestation.isnot(None),
    )
    if not cross_tenant:
        q = q.where(TriageDecision.tenant_id == _tenant_key(tenant_id))

    decisions = list((await db.execute(q)).scalars().all())
    if not decisions:
        return []

    decision_ids = [d.id for d in decisions]
    links_result = await db.execute(
        select(DecisionFindingLink).where(
            DecisionFindingLink.decision_id.in_(decision_ids),
            DecisionFindingLink.unlinked_at.is_(None),
        )
    )
    links = list(links_result.scalars().all())
    link_by_decision: dict[str, DecisionFindingLink] = {}
    for link in links:
        link_by_decision[link.decision_id] = link

    finding_ids = [link.finding_id for link in links]
    findings_by_id: dict[str, Finding] = {}
    if finding_ids:
        findings_result = await db.execute(
            select(Finding).where(Finding.id.in_(finding_ids))
        )
        findings_by_id = {f.id: f for f in findings_result.scalars().all()}

    out: list[dict[str, Any]] = []
    for decision in decisions:
        link = link_by_decision.get(decision.id)
        finding = findings_by_id.get(link.finding_id) if link else None
        record = _waiver_record_from_decision(
            decision,
            finding=finding,
            finding_id=link.finding_id if link else decision.last_finding_id,
            linked=finding is not None,
        )
        if asset_id and not _waiver_matches_asset(record, asset_id):
            continue
        out.append(record)
    return out


def waiver_records_for_export(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize ledger waiver rows for CSV/JSON/PDF export."""
    out: list[dict[str, Any]] = []
    for rec in records:
        att = rec.get("attestation") if isinstance(rec.get("attestation"), dict) else {}
        out.append(
            {
                "decisionId": rec.get("decisionId"),
                "subjectKey": rec.get("subjectKey"),
                "findingId": rec.get("findingId"),
                "linked": rec.get("linked"),
                "cveId": rec.get("cveId"),
                "ruleId": rec.get("ruleId"),
                "title": rec.get("title"),
                "severity": rec.get("severity"),
                "component": rec.get("component"),
                "image": rec.get("image"),
                "waiverRef": att.get("waiverRef"),
                "approver": att.get("approver"),
                "approverTitle": att.get("approverTitle"),
                "approvedAt": att.get("approvedAt"),
                "expiresAt": att.get("expiresAt"),
                "controlRef": rec.get("controlRef"),
                "justification": rec.get("justification"),
            }
        )
    return out


def _finding_row_to_waiver(f: dict[str, Any]) -> dict[str, Any]:
    att = f.get("attestation") if isinstance(f.get("attestation"), dict) else {}
    return {
        "decisionId": None,
        "subjectKey": None,
        "findingId": f.get("id"),
        "linked": True,
        "cveId": f.get("cveId"),
        "ruleId": f.get("ruleId"),
        "title": f.get("title"),
        "severity": f.get("severity"),
        "component": f.get("component"),
        "image": f.get("image"),
        "waiverRef": att.get("waiverRef"),
        "approver": att.get("approver"),
        "approverTitle": att.get("approverTitle"),
        "approvedAt": att.get("approvedAt"),
        "expiresAt": att.get("expiresAt"),
        "controlRef": f.get("controlRef"),
        "justification": f.get("justification"),
    }


async def build_waiver_export_records(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    cross_tenant: bool,
    finding_rows: list[dict],
) -> list[dict[str, Any]]:
    """
    Prefer durable ledger waivers; merge in finding-only waivers not yet backfilled.
    """
    ledger_rows = waiver_records_for_export(
        await list_waiver_decisions(
            db, tenant_id=tenant_id, cross_tenant=cross_tenant
        )
    )
    accepted = [f for f in finding_rows if (f.get("status") or "") == "Risk Accepted"]
    if ledger_rows:
        covered = {str(r.get("findingId")) for r in ledger_rows if r.get("findingId")}
        for f in accepted:
            if str(f.get("id") or "") in covered:
                continue
            ledger_rows.append(_finding_row_to_waiver(f))
        return ledger_rows

    return [_finding_row_to_waiver(f) for f in accepted]


async def backfill_decisions_from_findings(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    cross_tenant: bool = False,
    limit: int = 5000,
) -> dict[str, int]:
    """Create ledger rows for findings that already have triage decisions."""
    if not get_settings().decision_ledger_enabled:
        return {"created": 0, "skipped": 0, "scanned": 0}

    from types import SimpleNamespace

    from app.core.auth import tenant_filter

    q = select(Finding).where(Finding.status.in_(tuple(_RECORDABLE_STATUSES)))
    if not cross_tenant:
        ctx = SimpleNamespace(tenant_id=tenant_id, cross_tenant=False)
        q = q.where(tenant_filter(Finding, ctx))
    if limit > 0:
        q = q.limit(limit)

    findings = list((await db.execute(q)).scalars().all())
    created = 0
    skipped = 0
    # ponytail: per-finding resolution, fine for a one-time admin backfill under `limit`
    for finding in findings:
        candidates = await _candidates_for_finding(db, finding)
        if not candidates:
            skipped += 1
            continue
        primary = candidates[0]
        existing = await db.scalar(
            select(TriageDecision).where(
                TriageDecision.tenant_id == _tenant_key(finding.tenant_id),
                TriageDecision.subject_key == primary.subject_key,
            )
        )
        if existing:
            skipped += 1
            continue
        row = await record_decision_from_finding(
            db, finding, user="system@backfill", reason="backfill"
        )
        if row:
            created += 1
        else:
            skipped += 1
    return {"created": created, "skipped": skipped, "scanned": len(findings)}


async def expire_decision_waivers(db: AsyncSession) -> int:
    """Expire waivers in the ledger and reopen linked findings."""
    if not get_settings().decision_ledger_enabled:
        return 0

    today = datetime.now(timezone.utc).date().isoformat()
    result = await db.execute(
        select(TriageDecision).where(
            TriageDecision.status == Status.RiskAccepted.value,
            TriageDecision.attestation.isnot(None),
        )
    )
    decisions = list(result.scalars().all())
    count = 0
    now = _now()

    for decision in decisions:
        att = dict(decision.attestation or {})
        if not _is_waiver_expired(att.get("expiresAt"), today=today):
            continue

        waiver_ref = att.get("waiverRef", "")
        expires_at = att.get("expiresAt", "")
        decision.status = Status.Open.value
        att["expiredAt"] = _now().isoformat() + "Z"
        decision.attestation = att
        decision.decision_version = (decision.decision_version or 0) + 1
        decision.updated_by = "system@waiver-expiry"
        decision.updated_at = now

        db.add(
            TriageDecisionRevision(
                id=_new_revision_id(),
                decision_id=decision.id,
                revision=decision.decision_version,
                snapshot=_decision_snapshot(decision),
                actor_id="system@waiver-expiry",
                reason="waiver_expired",
                created_at=now,
            )
        )

        links = list(
            (
                await db.execute(
                    select(DecisionFindingLink).where(
                        DecisionFindingLink.decision_id == decision.id,
                        DecisionFindingLink.unlinked_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        # ponytail: per-link finding fetch, fine for a daily batch; batch-load if it grows
        for link in links:
            finding = await db.get(Finding, link.finding_id)
            if not finding:
                continue
            if finding.status != Status.RiskAccepted:
                continue
            finding.status = Status.Open
            finding.previous_status = Status.RiskAccepted.value
            audit = list(finding.audit or [])
            audit.append(
                {
                    "ts": _now().isoformat() + "Z",
                    "user": "system",
                    "action": "Waiver expired — auto-reopened",
                    "note": f"Waiver {waiver_ref} expired {expires_at}",
                }
            )
            finding.audit = audit
            link.applied_decision_version = decision.decision_version

        await emit_audit_event(
            db,
            trace_id=new_trace_id(),
            event_type="decision.waiver_expired",
            actor_type="system",
            actor_id="system@waiver-expiry",
            decision_name="waiver_expiry",
            decision_reason_code="attestation_expired",
            decision_result=Status.Open.value,
            data={
                "decision_id": decision.id,
                "subject_key": decision.subject_key,
                "waiver_ref": waiver_ref,
                "expires_at": expires_at,
            },
        )
        count += 1

    if count:
        await db.commit()
    return count
