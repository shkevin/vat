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

# Replay dedup stays fingerprint-based; correlation links rows that share a typed key across sources.
LINKABLE_CONFIDENCES = frozenset({"high", "medium"})


def select_correlation_cluster(
    *, correlation_key: str, tenant_id: str | None
) -> Select[tuple[Finding]]:
    """
    Deterministic cluster query: same typed key, same tenant scope (NULL matches NULL only).
    Canonical row is cluster[0] ordered by created_at, then id.
    """
    q = select(Finding).where(Finding.correlation_key == correlation_key)
    if tenant_id is None:
        q = q.where(Finding.tenant_id.is_(None))
    else:
        q = q.where(Finding.tenant_id == tenant_id)
    return q.order_by(Finding.created_at.asc(), Finding.id.asc())


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
    tenant + correlation_key cluster when confidence is high or medium.

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

    if conf not in LINKABLE_CONFIDENCES:
        await emit_audit_event(
            db,
            trace_id=tid,
            event_type="dedup.correlation.skipped",
            actor_type="system",
            source_id=source_id,
            parser_id=parser_id,
            finding_id=finding.id,
            decision_name="correlation_link",
            decision_reason_code="confidence_below_policy",
            decision_confidence="high",
            decision_result="skipped",
            data={
                "finding_id": finding.id,
                "correlation_confidence": finding.correlation_confidence,
            },
        )
        await db.flush()
        return

    tenant_id = finding.tenant_id
    q = select_correlation_cluster(correlation_key=key, tenant_id=tenant_id)

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

    for row in cluster[1:]:
        if row.correlated_to != canonical_id:
            row.correlated_to = canonical_id

    subject = next(r for r in cluster if r.id == finding.id)
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
    else:
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
            decision_confidence=conf or "medium",
            decision_result="linked",
            data={
                "canonical_finding_id": canonical_id,
                "correlation_key": key,
            },
        )
    await db.flush()
