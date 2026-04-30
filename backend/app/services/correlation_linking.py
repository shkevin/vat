"""Cross-source correlation linking (link-only policy). PRD §8.2.

Enabled by default after each ingest when ``Settings.correlation_linking_enabled`` is true
(``VAT_CORRELATION_LINKING_ENABLED``, default true). There is no per-request toggle; turning it off
is a deployment-level safety valve only.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.services.audit_events import emit_audit_event, new_trace_id
from app.services.correlation_edges import upsert_edge
from app.services.correlation_scoring import score_finding_pair


def select_correlation_cluster(
    *,
    correlation_key: str,
    tenant_id: str | None,
    for_update: bool = False,
) -> Select[tuple[Finding]]:
    """Deterministic cluster query: same typed key, same tenant scope (NULL
    matches NULL only). Canonical row is cluster[0] ordered by created_at,
    then id.

    ``for_update=True`` adds ``SELECT ... FOR UPDATE`` so concurrent ingests
    for the same correlation_key serialize on the cluster rows. Without it,
    two writers can both decide to link a peer to the canonical and race on
    the unique-edge constraint, leaving one transaction rolled back with no
    edge persisted. The lock is per-row, so unrelated clusters proceed in
    parallel.
    """
    q = select(Finding).where(Finding.correlation_key == correlation_key)
    if tenant_id is None:
        q = q.where(Finding.tenant_id.is_(None))
    else:
        q = q.where(Finding.tenant_id == tenant_id)
    q = q.order_by(Finding.created_at.asc(), Finding.id.asc())
    if for_update:
        q = q.with_for_update()
    return q


async def apply_correlation_linking(
    db: AsyncSession,
    finding: Any,
    trace_id: str | None,
    *,
    source_id: str | None = None,
    parser_id: str | None = None,
) -> None:
    """
    Link-only policy: set correlated_to to the oldest finding (canonical) in the same
    tenant + correlation_key cluster when score tier is high or medium.

    Emits dedup.correlation.linked or dedup.correlation.skipped for this finding only.

    ``finding`` is duck-typed (typically ORM ``Finding``): uses ``id``, ``correlation_key``,
    ``correlation_confidence``, ``tenant_id``.
    """
    tid = trace_id or new_trace_id()
    key = finding.correlation_key
    conf = (finding.correlation_confidence or "").strip().lower()

    if not key:
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="no_correlation_key",
            decision_confidence="high",
            decision_result="skipped",
            data={"finding_id": finding.id},
        )
        await db.flush()
        return

    tenant_id = finding.tenant_id
    q = select_correlation_cluster(
        correlation_key=key, tenant_id=tenant_id, for_update=True
    )

    result = await db.execute(q)
    cluster = list(result.scalars().all())

    cluster_ids = {r.id for r in cluster}
    if finding.id not in cluster_ids:
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="cluster_membership_mismatch",
            decision_confidence="high",
            decision_result="skipped",
            data={
                "finding_id": finding.id,
                "correlation_key": key,
                "cluster_size": len(cluster),
            },
        )
        await db.flush()
        return

    if len(cluster) <= 1:
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="no_peer",
            decision_confidence="high",
            decision_result="skipped",
            data={"finding_id": finding.id, "correlation_key": key},
        )
        await db.flush()
        return

    canonical = cluster[0]
    canonical_id = canonical.id
    action_by_id: dict[str, str] = {canonical_id: "cluster_root"}
    score_by_id: dict[str, float] = {}

    for row in cluster[1:]:
        decision = await score_finding_pair(db, canonical, row)
        tier = decision["tier"]
        score = float(decision["score"])
        score_by_id[row.id] = score
        if tier in {"high", "medium"}:
            if row.correlated_to != canonical_id:
                row.correlated_to = canonical_id
            await upsert_edge(
                db,
                finding_id_left=canonical_id,
                finding_id_right=row.id,
                edge_type="same_correlation_key",
                confidence=tier,
                evidence={
                    "correlation_key": key,
                    "score": score,
                    "reasons": decision["reasons"],
                    "crosswalk_matches": decision["evidence"].get(
                        "crosswalk_matches", []
                    ),
                },
                created_by="system",
                trace_id=tid,
                source_id=source_id,
                parser_id=parser_id,
            )
            action_by_id[row.id] = "linked"
            continue
        action_by_id[row.id] = "skipped_low_score"

    subject = next(r for r in cluster if r.id == finding.id)
    subject_action = action_by_id.get(subject.id, "cluster_root")
    if subject.id == canonical_id:
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="cluster_root",
            decision_confidence="high",
            decision_result="skipped",
            data={
                "finding_id": finding.id,
                "canonical_finding_id": canonical_id,
                "correlation_key": key,
            },
        )
    elif subject_action == "skipped_low_score":
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="score_below_policy",
            decision_confidence=conf or "low",
            decision_result="skipped",
            data={
                "canonical_finding_id": canonical_id,
                "correlation_key": key,
                "score": score_by_id.get(finding.id),
            },
        )
    else:
        linked_score = score_by_id.get(finding.id)
        linked_confidence = "high"
        if linked_score is not None and linked_score < 0.85:
            linked_confidence = "medium"
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.linked",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="same_correlation_key",
            decision_confidence=linked_confidence,
            decision_result="linked",
            data={
                "canonical_finding_id": canonical_id,
                "correlation_key": key,
                "score": score_by_id.get(finding.id),
            },
        )
    await db.flush()
