"""Identifier fact extraction and persistence for findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding_identifier import FindingIdentifier


def _norm(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value).strip().lower()
    return ""


def extract_identifier_facts(finding: Any) -> list[tuple[str, str, str]]:
    facts: list[tuple[str, str, str]] = []
    for namespace, attr, confidence in (
        ("cve_id", "cve_id", "high"),
        ("rule_id", "rule_id", "medium"),
        ("stable_rule_key", "stable_rule_key", "high"),
        ("benchmark_family", "benchmark_family", "medium"),
        ("control_ref", "control_ref", "medium"),
        ("ecosystem", "ecosystem", "medium"),
    ):
        value = _norm(getattr(finding, attr, None))
        if value:
            facts.append((namespace, value, confidence))
    return facts


async def upsert_identifier_facts_for_finding(
    db: AsyncSession,
    *,
    finding: Any,
    source: str = "ingest",
) -> None:
    finding_id = _norm(getattr(finding, "id", None))
    if not finding_id:
        return
    for namespace, value, confidence in extract_identifier_facts(finding):
        try:
            row = (
                await db.execute(
                    select(FindingIdentifier).where(
                        FindingIdentifier.finding_id == finding_id,
                        FindingIdentifier.namespace == namespace,
                        FindingIdentifier.value == value,
                        FindingIdentifier.source == source,
                    )
                )
            ).scalar_one_or_none()
        except Exception as exc:
            if "finding_identifiers" in str(exc) and "does not exist" in str(exc):
                return
            raise
        if row is None:
            db.add(
                FindingIdentifier(
                    finding_id=finding_id,
                    namespace=namespace,
                    value=value,
                    confidence=confidence,
                    source=source,
                    metadata_json={},
                )
            )
        else:
            row.confidence = confidence


async def list_identifier_facts_for_finding(
    db: AsyncSession, *, finding_id: str
) -> list[tuple[str, str]]:
    fid = _norm(finding_id)
    if not fid:
        return []
    try:
        rows = (
            await db.execute(
                select(FindingIdentifier).where(FindingIdentifier.finding_id == fid)
            )
        ).scalars().all()
    except Exception as exc:
        if "finding_identifiers" in str(exc) and "does not exist" in str(exc):
            return []
        raise
    return [(r.namespace, r.value) for r in rows]

