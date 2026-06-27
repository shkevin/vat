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
)

# Terminal compliance decisions auto-apply on re-import (design should_apply policy).
_TERMINAL_DECISION_STATUSES = frozenset(
    {
        Status.RiskAccepted.value,
        Status.FalsePositive.value,
        Status.Suppressed.value,
        Status.NotApplicable.value,
        Status.Mitigated.value,
        Status.Duplicate.value,
    }
)

# Approved/Rejected are reviewer judgements — never auto-applied; flagged for confirmation.
_REVIEW_REQUIRED_STATUSES = frozenset(
    {Status.Approved.value, Status.Rejected.value}
)

# Statuses a stored decision acts on at all (apply or flag).
_AUTO_APPLY_DECISION_STATUSES = _TERMINAL_DECISION_STATUSES | _REVIEW_REQUIRED_STATUSES

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
    conflict: bool = False


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


def _parse_audit_ts(ts: object) -> datetime | None:
    text = str(ts or "").strip().rstrip("Z")
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _finding_has_newer_human_edit(
    finding: Finding, decision: TriageDecision
) -> bool:
    """True when the finding was edited by a human after the decision's last update."""
    decision_updated = getattr(decision, "updated_at", None)
    if not decision_updated:
        return False
    latest: datetime | None = None
    for entry in getattr(finding, "audit", None) or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("user") or "").strip().lower() in ("", "system"):
            continue
        ts = _parse_audit_ts(entry.get("ts"))
        if ts and (latest is None or ts > latest):
            latest = ts
    # decision.updated_at is naive UTC (utcnow); audit ts are naive UTC too.
    return bool(latest and latest > decision_updated)


def decision_apply_action(finding: Finding, decision: TriageDecision) -> str:
    """Return 'apply', 'skip', or 'conflict' for re-linking a decision to a finding.

    Policy (design should_apply):
    - Approved/Rejected are reviewer judgements → never auto-applied (conflict to confirm).
    - Terminal compliance states auto-apply onto pre-decision findings.
    - Re-apply when the decision is newer than what the finding last reflected.
    - Never clobber a finding a human edited after the decision → conflict.
    """
    dstatus = decision.status
    fstatus = finding.status.value

    if dstatus in _REVIEW_REQUIRED_STATUSES:
        return "skip" if fstatus == dstatus else "conflict"
    if dstatus not in _TERMINAL_DECISION_STATUSES:
        return "skip"

    if fstatus in _PRE_DECISION_STATUSES:
        return "apply"

    link_applied = getattr(finding, "_decision_applied_version", None)
    decision_is_newer = link_applied is not None and decision.decision_version > link_applied
    if fstatus == dstatus and not decision_is_newer:
        return "skip"
    # Applying would change the finding — don't overwrite newer human work.
    if _finding_has_newer_human_edit(finding, decision):
        return "conflict"
    return "apply"


def should_apply_decision(finding: Finding, decision: TriageDecision) -> bool:
    """Backwards-compatible boolean wrapper over decision_apply_action."""
    return decision_apply_action(finding, decision) == "apply"


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

    action = decision_apply_action(finding, decision)
    applied = action == "apply"
    if applied:
        apply_decision_projection(finding, decision)

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

    if action == "conflict":
        # Decision differs from a finding a human edited (or needs Approved/Rejected
        # confirmation); link but don't project — surface for reviewer follow-up.
        await emit_audit_event(
            db,
            trace_id=trace_id or new_trace_id(),
            event_type="decision.relink.conflict",
            actor_type="system",
            finding_id=finding.id,
            decision_name="decision_relink",
            decision_reason_code=matched.kind,
            decision_confidence=matched.confidence,
            decision_result=decision.status,
            data={
                "decision_id": decision.id,
                "subject_key": decision.subject_key,
                "finding_status": finding.status.value,
            },
        )
    elif applied or existing_link is None:
        # Audit only real changes / first link; no-op re-imports would flood the ledger.
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
        conflict=action == "conflict",
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


def _rekey_subject_key_asset(
    subject_key: str, old_norm: str, new_norm: str
) -> str | None:
    """Substitute the canonical-asset token in a primary DSK (asset is field index 4)."""
    parts = subject_key.split(":")
    if len(parts) < 5 or parts[0] != "decision":
        return None
    asset_seg = parts[4].split("|")
    if not asset_seg or asset_seg[0] != old_norm:
        return None
    asset_seg[0] = new_norm
    parts[4] = "|".join(asset_seg)
    return ":".join(parts)


async def register_decision_aliases_for_asset_merge(
    db: AsyncSession, *, old_asset_id: str, new_asset_id: str
) -> int:
    """Alias decisions keyed on a merged-away asset to their new canonical DSK.

    After asset ``old`` merges into ``new``, future findings resolve canonical→new
    and compute the new DSK; this alias bridges them to the decision recorded under
    the old key so a prior Risk Accepted survives the merge.
    """
    if not get_settings().decision_ledger_enabled:
        return 0
    from app.services.dedup import normalize

    old_norm = normalize(old_asset_id or "")
    new_norm = normalize(new_asset_id or "")
    if not old_norm or not new_norm or old_norm == new_norm:
        return 0

    # ponytail: LIKE narrows to decisions carrying the old asset token (small ledger);
    # _rekey re-confirms the token is in asset position before aliasing.
    rows = (
        (
            await db.execute(
                select(TriageDecision).where(
                    TriageDecision.subject_key.like(f"decision:v1:%:{old_norm}|%")
                )
            )
        )
        .scalars()
        .all()
    )
    count = 0
    for decision in rows:
        new_key = _rekey_subject_key_asset(decision.subject_key, old_norm, new_norm)
        if not new_key or new_key == decision.subject_key:
            continue
        await register_subject_alias(
            db,
            tenant_id=decision.tenant_id,
            alias_key=new_key,
            canonical_key=decision.subject_key,
            reason="asset_merge",
        )
        count += 1
    return count


async def decision_provenance(
    db: AsyncSession, finding: Finding
) -> dict[str, Any] | None:
    """Ledger provenance for a finding's detail view (Phase 3 read-path).

    Annotates rather than overrides: the finding row already reflects applied
    decisions (projection cache), so we surface the durable link + a conflict flag
    when a linked decision was NOT applied (e.g. a newer human edit) instead of
    clobbering the cached compliance fields.
    """
    if not get_settings().decision_ledger_enabled:
        return None
    link = await db.scalar(
        select(DecisionFindingLink).where(
            DecisionFindingLink.finding_id == finding.id,
            DecisionFindingLink.unlinked_at.is_(None),
        )
    )
    if not link:
        return None
    decision = await db.get(TriageDecision, link.decision_id)
    if not decision:
        return None
    fstatus = getattr(finding.status, "value", str(finding.status))
    return {
        "decisionId": decision.id,
        "subjectKey": decision.subject_key,
        "decisionVersion": decision.decision_version,
        "decisionLinkMethod": link.link_method,
        "decisionRelinked": link.link_method != "primary",
        "decisionConflict": (
            decision.status in _AUTO_APPLY_DECISION_STATUSES
            and decision.status != fstatus
        ),
    }


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


async def get_decision_detail(
    db: AsyncSession,
    *,
    tenant_id: str | None,
    cross_tenant: bool = False,
    subject_key: str | None = None,
    decision_id: str | None = None,
) -> dict[str, Any] | None:
    """Auditor drill-down: a decision + its append-only revision history + live links."""
    if not get_settings().decision_ledger_enabled:
        return None
    tenant = _tenant_key(tenant_id)

    q = select(TriageDecision)
    if decision_id:
        q = q.where(TriageDecision.id == decision_id)
    elif subject_key:
        q = q.where(TriageDecision.subject_key == subject_key)
    else:
        return None
    if not cross_tenant:
        q = q.where(TriageDecision.tenant_id == tenant)
    decision = await db.scalar(q)

    # Resolve a subject_key that's an alias of the canonical decision.
    if not decision and subject_key:
        alias = await db.get(
            DecisionSubjectAlias, {"tenant_id": tenant, "alias_key": subject_key}
        )
        if alias:
            aq = select(TriageDecision).where(
                TriageDecision.subject_key == alias.canonical_key
            )
            if not cross_tenant:
                aq = aq.where(TriageDecision.tenant_id == tenant)
            decision = await db.scalar(aq)
    if not decision:
        return None

    revisions = list(
        (
            await db.execute(
                select(TriageDecisionRevision)
                .where(TriageDecisionRevision.decision_id == decision.id)
                .order_by(TriageDecisionRevision.revision)
            )
        )
        .scalars()
        .all()
    )
    link_rows = list(
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

    return {
        "decision_id": decision.id,
        "tenant_id": decision.tenant_id,
        "subject_key": decision.subject_key,
        "finding_type": decision.finding_type,
        "status": decision.status,
        "decision_version": decision.decision_version,
        "justification": decision.justification,
        "compensating_controls": decision.compensating_controls,
        "reviewer_note": decision.reviewer_note,
        "attestation": decision.attestation,
        "identity_snapshot": decision.identity_snapshot,
        "created_by": decision.created_by,
        "created_at": decision.created_at.isoformat() if decision.created_at else None,
        "updated_by": decision.updated_by,
        "updated_at": decision.updated_at.isoformat() if decision.updated_at else None,
        "linked_finding_ids": [link.finding_id for link in link_rows],
        "revisions": [
            {
                "revision": r.revision,
                "actor_id": r.actor_id,
                "reason": r.reason,
                "snapshot": r.snapshot,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in revisions
        ],
    }


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


async def reconcile_decision_links(
    db: AsyncSession,
    *,
    tenant_id: str | None = None,
    cross_tenant: bool = True,
    limit: int = 5000,
) -> dict[str, int]:
    """Re-run decision re-linking across findings to repair drift (nightly job).

    Idempotent: findings without a matching decision are no-ops; matching ones get
    re-projected/linked and conflicts get flagged via ``decision.relink.conflict``.
    """
    if not get_settings().decision_ledger_enabled:
        return {"scanned": 0, "applied": 0, "conflicts": 0, "relinked": 0}

    from types import SimpleNamespace

    from app.core.auth import tenant_filter

    q = select(Finding)
    if not cross_tenant:
        ctx = SimpleNamespace(tenant_id=tenant_id, cross_tenant=False)
        q = q.where(tenant_filter(Finding, ctx))
    if limit > 0:
        q = q.limit(limit)

    findings = list((await db.execute(q)).scalars().all())
    scanned = applied = conflicts = relinked = 0
    # ponytail: per-finding resolve, fine nightly under `limit`; most are no-op skips
    for finding in findings:
        result = await resolve_and_apply_decision(db, finding)
        scanned += 1
        if result.decision_id:
            relinked += 1
        if result.applied:
            applied += 1
        if result.conflict:
            conflicts += 1
        if scanned % 500 == 0:
            await db.commit()
    await db.commit()
    return {
        "scanned": scanned,
        "applied": applied,
        "conflicts": conflicts,
        "relinked": relinked,
    }


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
