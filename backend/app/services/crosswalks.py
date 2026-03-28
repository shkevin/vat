"""Crosswalk ingestion and lookup services."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.crosswalk_entry import CrosswalkEntry
from app.models.crosswalk_run import CrosswalkRun


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def _checksum(source: str, source_version: str, entries: list[dict[str, Any]]) -> str:
    payload = f"{source}|{source_version}|{entries!r}"
    return hashlib.sha256(payload.encode()).hexdigest()


async def ingest_crosswalk_entries(
    db: AsyncSession,
    *,
    source: str,
    source_version: str,
    entries: list[dict[str, Any]],
    created_by: str | None = None,
    trace_id: str | None = None,
) -> CrosswalkRun:
    run_id = uuid.uuid4().hex
    run = CrosswalkRun(
        id=run_id,
        source=source,
        source_version=source_version,
        status="running",
        trace_id=trace_id,
        input_checksum=_checksum(source, source_version, entries),
        stats={},
        created_by=created_by,
        started_at=datetime.utcnow(),
    )
    db.add(run)
    await db.flush()

    inserted = 0
    updated = 0
    rejected = 0
    for e in entries:
        from_ns = _norm(e.get("from_namespace"))
        from_val = _norm(e.get("from_value"))
        to_ns = _norm(e.get("to_namespace"))
        to_val = _norm(e.get("to_value"))
        if not from_ns or not from_val or not to_ns or not to_val:
            rejected += 1
            continue

        existing = (
            await db.execute(
                select(CrosswalkEntry).where(
                    CrosswalkEntry.from_namespace == from_ns,
                    CrosswalkEntry.from_value == from_val,
                    CrosswalkEntry.to_namespace == to_ns,
                    CrosswalkEntry.to_value == to_val,
                    CrosswalkEntry.source == source,
                    CrosswalkEntry.source_version == source_version,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row = CrosswalkEntry(
                run_id=run_id,
                source=source,
                source_version=source_version,
                from_namespace=from_ns,
                from_value=from_val,
                to_namespace=to_ns,
                to_value=to_val,
                confidence=_norm(e.get("confidence") or "medium"),
                score=e.get("score"),
                active=bool(e.get("active", True)),
                metadata_json=e.get("metadata") or {},
                last_verified_at=datetime.utcnow(),
            )
            db.add(row)
            inserted += 1
        else:
            existing.run_id = run_id
            existing.confidence = _norm(e.get("confidence") or existing.confidence)
            existing.score = (
                e.get("score") if e.get("score") is not None else existing.score
            )
            existing.active = bool(e.get("active", True))
            existing.metadata_json = e.get("metadata") or existing.metadata_json or {}
            existing.last_verified_at = datetime.utcnow()
            existing.disabled_at = None if existing.active else datetime.utcnow()
            existing.disabled_reason = None if existing.active else "inactive from ingest"
            existing.updated_at = datetime.utcnow()
            updated += 1

    run.status = "completed"
    run.completed_at = datetime.utcnow()
    run.stats = {"inserted": inserted, "updated": updated, "rejected": rejected}
    return run


async def resolve_crosswalk_values(
    db: AsyncSession,
    *,
    from_namespace: str,
    from_value: str,
    to_namespace: str | None = None,
) -> list[CrosswalkEntry]:
    fns = _norm(from_namespace)
    fval = _norm(from_value)
    if not fns or not fval:
        return []
    clauses = [
        CrosswalkEntry.active.is_(True),
        CrosswalkEntry.from_namespace == fns,
        CrosswalkEntry.from_value == fval,
    ]
    if to_namespace:
        clauses.append(CrosswalkEntry.to_namespace == _norm(to_namespace))
    result = await db.execute(
        select(CrosswalkEntry)
        .where(and_(*clauses))
        .order_by(CrosswalkEntry.updated_at.desc(), CrosswalkEntry.id.desc())
    )
    return list(result.scalars().all())


async def identifiers_crosswalk_match(
    db: AsyncSession,
    *,
    left: list[tuple[str, str]],
    right: list[tuple[str, str]],
) -> list[dict[str, str]]:
    """Return matching crosswalk bridges between two identifier sets."""
    if not left or not right:
        return []
    right_set = {(_norm(ns), _norm(val)) for ns, val in right if _norm(val)}
    matches: list[dict[str, str]] = []
    for from_ns, from_val in left:
        fns = _norm(from_ns)
        fval = _norm(from_val)
        if not fns or not fval:
            continue
        rows = await resolve_crosswalk_values(
            db, from_namespace=fns, from_value=fval, to_namespace=None
        )
        for row in rows:
            mapped = (_norm(row.to_namespace), _norm(row.to_value))
            if mapped in right_set:
                matches.append(
                    {
                        "from_namespace": fns,
                        "from_value": fval,
                        "to_namespace": mapped[0],
                        "to_value": mapped[1],
                        "source": row.source,
                        "source_version": row.source_version,
                        "confidence": row.confidence,
                    }
                )
    if matches:
        return matches
    # symmetric lookup (right -> left)
    left_set = {(_norm(ns), _norm(val)) for ns, val in left if _norm(val)}
    if not left_set:
        return []
    for from_ns, from_val in right:
        fns = _norm(from_ns)
        fval = _norm(from_val)
        if not fns or not fval:
            continue
        result = await db.execute(
            select(CrosswalkEntry).where(
                and_(
                    CrosswalkEntry.active.is_(True),
                    CrosswalkEntry.from_namespace == fns,
                    CrosswalkEntry.from_value == fval,
                    or_(
                        *[
                            and_(
                                CrosswalkEntry.to_namespace == lns,
                                CrosswalkEntry.to_value == lval,
                            )
                            for lns, lval in left_set
                        ]
                    ),
                )
            )
        )
        for row in result.scalars().all():
            matches.append(
                {
                    "from_namespace": row.from_namespace,
                    "from_value": row.from_value,
                    "to_namespace": row.to_namespace,
                    "to_value": row.to_value,
                    "source": row.source,
                    "source_version": row.source_version,
                    "confidence": row.confidence,
                }
            )
    return matches

