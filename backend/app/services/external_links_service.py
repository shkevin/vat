"""External links service — unified finding ↔ external issue association.

Source-agnostic and tracker-agnostic. Supports lookup, add link, get issue_id by adapter.
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from sqlalchemy import select, type_coerce
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding

LinkKind = Literal["tracker", "source"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_tracker_issue_id(finding: Finding, adapter_key: str) -> Optional[str]:
    """Get tracker issue_id for adapter. Returns None if no link."""
    links = finding.external_links or []
    for link in links:
        if (
            isinstance(link, dict)
            and link.get("kind") == "tracker"
            and link.get("adapter_key") == adapter_key
        ):
            return link.get("issue_id")
    return None


def get_tracker_issue_uuid(finding: Finding, adapter_key: str) -> Optional[str]:
    """Get tracker issue UUID for adapter (for Linear API filtering). Returns None if no link or no UUID stored."""
    links = finding.external_links or []
    for link in links:
        if (
            isinstance(link, dict)
            and link.get("kind") == "tracker"
            and link.get("adapter_key") == adapter_key
        ):
            return link.get("issue_uuid")
    return None


def get_source_issue_id(finding: Finding, adapter_key: str) -> Optional[str]:
    """Get source issue_id for adapter. Returns None if no link."""
    links = finding.external_links or []
    for link in links:
        if (
            isinstance(link, dict)
            and link.get("kind") == "source"
            and link.get("adapter_key") == adapter_key
        ):
            return link.get("issue_id")
    return None


def has_tracker_link(finding: Finding, adapter_key: Optional[str] = None) -> bool:
    """True if finding has a tracker link. If adapter_key given, checks that adapter."""
    links = finding.external_links or []
    for link in links:
        if isinstance(link, dict) and link.get("kind") == "tracker":
            if adapter_key is None or link.get("adapter_key") == adapter_key:
                return True
    return False


def remove_tracker_link(finding: Finding, adapter_key: str) -> bool:
    """Remove tracker link for adapter. Returns True if a link was removed."""
    links = finding.external_links or []
    before = len(links)
    links = [
        l
        for l in links
        if not (
            isinstance(l, dict)
            and l.get("kind") == "tracker"
            and l.get("adapter_key") == adapter_key
        )
    ]
    finding.external_links = links
    return len(links) < before


def add_tracker_link(
    finding: Finding,
    adapter_key: str,
    issue_id: str,
    url: Optional[str] = None,
    *,
    synced_fields: Optional[list[str]] = None,
    issue_uuid: Optional[str] = None,
) -> None:
    """Add or replace tracker link. Mutates finding.external_links in place.
    issue_uuid: optional Linear UUID for efficient API filtering (id: { in: [...] }).
    """
    links = list(finding.external_links or [])
    # Remove existing link for this adapter
    links = [
        l
        for l in links
        if not (
            isinstance(l, dict)
            and l.get("kind") == "tracker"
            and l.get("adapter_key") == adapter_key
        )
    ]
    link: dict = {
        "adapter_key": adapter_key,
        "kind": "tracker",
        "issue_id": issue_id,
        "url": url,
        "created_at": _now(),
        "last_synced_at": _now(),
        "synced_fields": synced_fields or [],
    }
    if issue_uuid:
        link["issue_uuid"] = issue_uuid
    links.append(link)
    finding.external_links = links


def add_source_link(
    finding: Finding,
    adapter_key: str,
    issue_id: str,
    url: Optional[str] = None,
) -> None:
    """Add or replace source link. Mutates finding.external_links in place."""
    links = list(finding.external_links or [])
    links = [
        l
        for l in links
        if not (
            isinstance(l, dict)
            and l.get("kind") == "source"
            and l.get("adapter_key") == adapter_key
        )
    ]
    link = {
        "adapter_key": adapter_key,
        "kind": "source",
        "issue_id": issue_id,
        "url": url,
        "created_at": _now(),
    }
    links.append(link)
    finding.external_links = links


def _is_uuid(value: str) -> bool:
    """True if value looks like a Linear/UUID format (e.g. 8f7e6d5c-4b3a-2198-7f6e-5d4c3b2a1098)."""
    import re

    return bool(
        value
        and re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            str(value).strip(),
            re.I,
        )
    )


async def find_finding_by_external_id(
    db: AsyncSession,
    adapter_key: str,
    issue_id: str,
) -> Optional[Finding]:
    """
    Find finding by adapter_key + issue_id. Works for any source or tracker.
    Returns first match when multiple findings share the same link (data integrity edge case).
    """
    needle = [{"adapter_key": adapter_key, "issue_id": issue_id}]
    stmt = (
        select(Finding)
        .where(Finding.external_links.op("@>")(type_coerce(needle, JSONB)))
        .order_by(Finding.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def find_finding_by_linear_issue_id_or_uuid(
    db: AsyncSession,
    issue_id: str,
    issue_uuid: Optional[str] = None,
) -> Optional[Finding]:
    """
    Find finding by Linear tracker link. Supports both issue_id (e.g. ENG-123) and issue_uuid.
    Linear webhooks send issueId as UUID; poll uses identifier. Try both for reliability.
    """
    # Try issue_id first (identifier like ENG-123)
    if issue_id:
        finding = await find_finding_by_external_id(db, "linear", issue_id)
        if finding:
            return finding
    # Try issue_uuid (Linear sends UUID in Comment.create webhook data.issueId)
    if issue_uuid:
        finding = await _find_finding_by_linear_uuid(db, issue_uuid)
        if finding:
            return finding
    # If single value looks like UUID, try as issue_uuid (webhook may send only UUID)
    if issue_id and _is_uuid(issue_id):
        finding = await _find_finding_by_linear_uuid(db, issue_id)
        if finding:
            return finding
    return None


async def _find_finding_by_linear_uuid(
    db: AsyncSession, issue_uuid: str
) -> Optional[Finding]:
    """Find finding by Linear issue UUID (stored in external_links issue_uuid)."""
    from sqlalchemy import text

    stmt = text("""
        SELECT f.id FROM findings f
        WHERE f.archived = false
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(f.external_links) AS elem
            WHERE elem->>'kind' = 'tracker'
              AND elem->>'adapter_key' = 'linear'
              AND elem->>'issue_uuid' = :uuid
          )
        ORDER BY f.created_at DESC
        LIMIT 1
    """)
    result = await db.execute(stmt, {"uuid": issue_uuid})
    row = result.fetchone()
    if not row:
        return None
    r = await db.execute(select(Finding).where(Finding.id == row[0]))
    return r.scalar_one_or_none()


def get_primary_tracker_id(finding: Finding, tracker_key: str) -> Optional[str]:
    """Get primary tracker issue_id for UI display. Returns first matching tracker link."""
    return get_tracker_issue_id(finding, tracker_key)


def get_all_tracker_links(finding: Finding) -> list[dict]:
    """Get all tracker links for a finding."""
    links = finding.external_links or []
    return [l for l in links if isinstance(l, dict) and l.get("kind") == "tracker"]


def get_all_source_links(finding: Finding) -> list[dict]:
    """Get all source links for a finding."""
    links = finding.external_links or []
    return [l for l in links if isinstance(l, dict) and l.get("kind") == "source"]


def get_source_issue_url(finding: Finding) -> Optional[str]:
    """Get URL to view finding in source (e.g. Aikido dashboard). Returns first source link with url."""
    for link in get_all_source_links(finding):
        url = link.get("url")
        if url and isinstance(url, str) and url.strip():
            return url.strip()
    return None


async def get_all_linear_tracker_issue_ids(
    db: AsyncSession,
) -> list[tuple[str, Optional[str]]]:
    """
    Get all (issue_id, issue_uuid) for findings with Linear tracker links.
    Used by poll to fetch only VAT-tracked issues. Returns deduplicated list.
    issue_uuid may be None for older links; caller should resolve or skip.
    """
    from sqlalchemy import text

    # Find findings where external_links contains a tracker link for linear
    stmt = text("""
        SELECT f.external_links
        FROM findings f
        WHERE f.archived = false
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(f.external_links) AS elem
            WHERE elem->>'kind' = 'tracker' AND elem->>'adapter_key' = 'linear'
          )
    """)
    result = await db.execute(stmt)
    rows = result.fetchall()
    seen: set[str] = set()
    out: list[tuple[str, Optional[str]]] = []
    for (links,) in rows:
        if not links:
            continue
        for link in links:
            if (
                not isinstance(link, dict)
                or link.get("kind") != "tracker"
                or link.get("adapter_key") != "linear"
            ):
                continue
            issue_id = link.get("issue_id")
            if not issue_id or issue_id in seen:
                continue
            seen.add(issue_id)
            out.append((issue_id, link.get("issue_uuid")))
    return out
