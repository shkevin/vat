"""Container asset observation and digest conflict helpers."""

from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_digest_conflict import AssetDigestConflict
from app.models.asset_observed_tag import AssetObservedTag
from app.models.finding import Finding
from app.parsers.image_digest import effective_image_digest
from app.schemas.vat import VatFindingSchema
from app.services.assets_service import _container_image_group_key


def _now_utc() -> datetime:
    return datetime.utcnow()


def _clean(value: str | None) -> str:
    return str(value or "").strip()


def _is_container_image_asset(image: str) -> bool:
    """
    True when ``image`` is a container asset path (VAT + registry-style refs).

    Observations are recorded only for these so package/repo assets are not polluted.
    """
    s = _clean(image)
    if not s:
        return False
    if "/images/" in s or "/operators/" in s:
        return True
    if s.lower().startswith("docker.io/"):
        return True
    if s.startswith("containers/") or s.startswith("operators/"):
        return True
    first = s.split("/", 1)[0]
    if "." in first or ":" in first or first in {"localhost", "docker.io"}:
        return True
    return False


def _canonical_observation_asset_id(image: str) -> str:
    """Match ``get_assets_with_findings`` / ingest correlation grouping keys."""
    s = _clean(image)
    if not s or not _is_container_image_asset(s):
        return s
    return _container_image_group_key(s, None)


async def record_container_asset_observation(
    db: AsyncSession,
    *,
    payload: VatFindingSchema,
    scan_session_id: str | None,
    source: str | None = None,
) -> None:
    """
    Record canonical asset tag observation and update digest conflict state.

    Observation count semantics:
    - Count increments once per new scan_session_id for asset+tag.
    - If scan_session_id is missing, increments per ingest event.
    """

    asset_id = _canonical_observation_asset_id(_clean(payload.image))
    tag = _clean(getattr(payload, "tag", None))
    if not asset_id or not tag:
        return
    if not _is_container_image_asset(asset_id):
        return

    digest = effective_image_digest(
        getattr(payload, "image_digest", None),
        payload.image,
    )
    now = _now_utc()

    row = (
        await db.execute(
            select(AssetObservedTag).where(
                AssetObservedTag.asset_id == asset_id,
                AssetObservedTag.tag == tag,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        db.add(
            AssetObservedTag(
                asset_id=asset_id,
                tag=tag,
                observation_count=1,
                last_scan_session_id=scan_session_id,
                last_digest=digest,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    else:
        row.last_seen_at = now
        row.last_digest = digest or row.last_digest
        if scan_session_id:
            if row.last_scan_session_id != scan_session_id:
                row.observation_count = int(row.observation_count or 0) + 1
                row.last_scan_session_id = scan_session_id
        else:
            row.observation_count = int(row.observation_count or 0) + 1

    if digest:
        await _upsert_digest_conflict(
            db, asset_id=asset_id, tag=tag, digest=digest, source=source, now=now
        )


async def ensure_container_tags_observed(
    db: AsyncSession,
    *,
    asset_id: str,
    tags: list[str],
) -> None:
    """
    Ensure one ``asset_observed_tags`` row per tag for ``asset_id`` (no digest required).

    Used when the source lists multiple tags (e.g. Aikido GET /containers) so the VAT UI
    can show the full tag set before per-tag findings or SBOM rows exist.
    """
    asset_id = _canonical_observation_asset_id(_clean(asset_id))
    if not asset_id or not _is_container_image_asset(asset_id):
        return
    now = _now_utc()
    for raw in tags:
        tag = _clean(raw)
        if not tag:
            continue
        row = (
            await db.execute(
                select(AssetObservedTag).where(
                    AssetObservedTag.asset_id == asset_id,
                    AssetObservedTag.tag == tag,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            db.add(
                AssetObservedTag(
                    asset_id=asset_id,
                    tag=tag,
                    observation_count=1,
                    last_scan_session_id=None,
                    last_digest=None,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
        else:
            row.last_seen_at = now


async def upsert_digest_from_external_scan(
    db: AsyncSession,
    *,
    asset_id: str,
    tag: str,
    digest: str,
) -> None:
    """
    Record or refresh ``last_digest`` for a container asset+tag from SBOM/API sync
    (no ``VatFindingSchema``). Used by Aikido container license export enrichment.
    """
    asset_id = _canonical_observation_asset_id(_clean(asset_id))
    tag = _clean(tag)
    norm = normalize_image_digest(digest)
    if not asset_id or not tag or not norm:
        return
    if not _is_container_image_asset(asset_id):
        return
    now = _now_utc()
    row = (
        await db.execute(
            select(AssetObservedTag).where(
                AssetObservedTag.asset_id == asset_id,
                AssetObservedTag.tag == tag,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        db.add(
            AssetObservedTag(
                asset_id=asset_id,
                tag=tag,
                observation_count=1,
                last_scan_session_id=None,
                last_digest=norm,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    else:
        row.last_digest = norm
        row.last_seen_at = now
    # External SBOM/API enrichment (e.g. Aikido) is a registry-side observation.
    await _upsert_digest_conflict(
        db, asset_id=asset_id, tag=tag, digest=norm, source=None, now=now
    )


_FLOATING_TAGS = frozenset(
    {
        "latest", "develop", "main", "master", "stable", "edge", "nightly",
        "dev", "prod", "production", "staging", "canary", "head", "rolling",
        "release", "snapshot",
    }
)
# Immutable-looking: semver (v1.19.4, 1.2.3[-suffix]), git-sha tags (sha-<hex>),
# bare digests, or date stamps (20260627...). Everything else is treated as
# mutable/floating.
_IMMUTABLE_TAG_RE = re.compile(
    r"^(v?\d+(\.\d+)+([.\-+].*)?|sha-[0-9a-f]{7,}|[0-9a-f]{12,}|\d{8}.*)$"
)


def _is_mutable_tag(tag: str | None) -> bool:
    """True when the tag is expected to move (floating/branch) rather than pin a
    fixed image. Mutable tags keep the latest observed digest (Aikido-style
    last-write-wins) instead of raising a digest conflict."""
    t = (tag or "").strip().lower()
    if not t or t in _FLOATING_TAGS:
        return True
    return _IMMUTABLE_TAG_RE.match(t) is None


def _digest_scan_vantage(source: str | None) -> str:
    """Classify a finding ``source`` by how it observes the image digest.

    Runtime scanners (node agents) read the digest from the local container
    runtime (containerd); for a multi-arch image that is the platform/host
    manifest digest, which legitimately differs from the registry index digest a
    registry-pull scanner (inventory worker, Aikido, CI) reports for the same
    tag. Comparing across vantages flags the same image as a conflict, so we only
    treat a tag as conflicting when a single vantage observes multiple digests.

    ponytail: vantage is inferred from the node-agent source-id convention
    (``node-<node>-<parser>``); revisit if findings gain an explicit scan-method.
    """
    return "runtime" if (source or "").strip().lower().startswith("node-") else "registry"


async def _upsert_digest_conflict(
    db: AsyncSession,
    *,
    asset_id: str,
    tag: str,
    digest: str,
    source: str | None,
    now: datetime,
) -> None:
    if _is_mutable_tag(tag):
        # Floating tag (latest/develop/branch): the digest is meant to move, so we
        # keep the latest observed digest (asset_observed_tags.last_digest, already
        # updated by the caller) and never raise a conflict — last-write-wins, as
        # Aikido does. Clear any pre-existing row so the UI stops nagging.
        existing = (
            await db.execute(
                select(AssetDigestConflict).where(
                    AssetDigestConflict.asset_id == asset_id,
                    AssetDigestConflict.tag == tag,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            await db.delete(existing)
        return

    # Bucket every recorded digest for this tag by scan vantage. A real conflict
    # is one vantage seeing the same tag at two digests (the tag actually moved);
    # a difference only across vantages is a multi-arch index-vs-platform
    # representation of the same image and must not be flagged.
    rows = (
        await db.execute(
            select(Finding.source, Finding.image_digest).where(
                Finding.image == asset_id,
                Finding.tag == tag,
                Finding.image_digest.is_not(None),
            )
        )
    ).all()
    by_vantage: dict[str, set[str]] = {}
    for f_source, f_digest in rows:
        d = str(f_digest or "").strip()
        if d:
            by_vantage.setdefault(_digest_scan_vantage(f_source), set()).add(d)
    by_vantage.setdefault(_digest_scan_vantage(source), set()).add(digest)

    conflicting = sorted(
        {d for ds in by_vantage.values() if len(ds) >= 2 for d in ds}
    )

    conflict = (
        await db.execute(
            select(AssetDigestConflict).where(
                AssetDigestConflict.asset_id == asset_id,
                AssetDigestConflict.tag == tag,
            )
        )
    ).scalar_one_or_none()

    if not conflicting:
        # No within-vantage conflict — drop any stale/false-positive row so the
        # UI clears (derived telemetry, safe to delete and re-derive).
        if conflict is not None:
            await db.delete(conflict)
        return

    if conflict is None:
        db.add(
            AssetDigestConflict(
                asset_id=asset_id,
                tag=tag,
                status="open",
                digests=conflicting,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        return

    previous = set(str(d).strip() for d in (conflict.digests or []) if str(d).strip())
    conflict.digests = conflicting
    conflict.last_seen_at = now
    if set(conflicting) - previous:
        conflict.status = "open"
        conflict.acknowledged_at = None
        conflict.acknowledged_by = None


async def migrate_observations_for_asset_merge(
    db: AsyncSession,
    *,
    source_asset_id: str,
    canonical_target: str,
) -> dict[str, int]:
    """
    Move ``asset_observed_tags`` and ``asset_digest_conflicts`` from a merge source
    to the canonical asset. When the same tag exists on both sides, merge rows
    (counts, timestamps, digests) and delete the source row.

    Call during manual asset merge so tag/digest telemetry stays with the surviving
    list asset.
    """
    src = _clean(source_asset_id)
    tgt = _clean(canonical_target)
    if not src or not tgt or src == tgt:
        return {
            "observed_tags_moved": 0,
            "observed_tags_merged": 0,
            "digest_conflicts_moved": 0,
            "digest_conflicts_merged": 0,
        }

    out = {
        "observed_tags_moved": 0,
        "observed_tags_merged": 0,
        "digest_conflicts_moved": 0,
        "digest_conflicts_merged": 0,
    }

    obs_src = list(
        (
            await db.execute(
                select(AssetObservedTag).where(AssetObservedTag.asset_id == src)
            )
        )
        .scalars()
        .all()
    )
    for row in obs_src:
        existing = (
            await db.execute(
                select(AssetObservedTag).where(
                    AssetObservedTag.asset_id == tgt,
                    AssetObservedTag.tag == row.tag,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row.asset_id = tgt
            out["observed_tags_moved"] += 1
            continue
        e_first, e_last = existing.first_seen_at, existing.last_seen_at
        r_first, r_last = row.first_seen_at, row.last_seen_at
        existing.observation_count = int(existing.observation_count or 0) + int(
            row.observation_count or 0
        )
        if r_first and e_first:
            existing.first_seen_at = min(e_first, r_first)
        elif r_first:
            existing.first_seen_at = r_first
        if r_last and e_last:
            existing.last_seen_at = max(e_last, r_last)
        elif r_last:
            existing.last_seen_at = r_last
        r_d = _clean(row.last_digest)
        e_d = _clean(existing.last_digest)
        if r_last and (not e_last or r_last >= e_last):
            if r_d:
                existing.last_digest = row.last_digest
        elif r_d and not e_d:
            existing.last_digest = row.last_digest
        if row.last_scan_session_id and (
            not existing.last_scan_session_id
            or (r_last and e_last and r_last >= e_last)
        ):
            existing.last_scan_session_id = row.last_scan_session_id
        await db.delete(row)
        out["observed_tags_merged"] += 1

    dc_src = list(
        (
            await db.execute(
                select(AssetDigestConflict).where(AssetDigestConflict.asset_id == src)
            )
        )
        .scalars()
        .all()
    )
    for row in dc_src:
        existing = (
            await db.execute(
                select(AssetDigestConflict).where(
                    AssetDigestConflict.asset_id == tgt,
                    AssetDigestConflict.tag == row.tag,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row.asset_id = tgt
            out["digest_conflicts_moved"] += 1
            continue
        prev_e = set(str(d).strip() for d in (existing.digests or []) if str(d).strip())
        prev_r = set(str(d).strip() for d in (row.digests or []) if str(d).strip())
        merged = sorted(prev_e | prev_r)
        existing.digests = merged
        if row.first_seen_at and existing.first_seen_at:
            existing.first_seen_at = min(existing.first_seen_at, row.first_seen_at)
        elif row.first_seen_at:
            existing.first_seen_at = row.first_seen_at
        if row.last_seen_at and existing.last_seen_at:
            existing.last_seen_at = max(existing.last_seen_at, row.last_seen_at)
        elif row.last_seen_at:
            existing.last_seen_at = row.last_seen_at
        if len(merged) >= 2:
            existing.status = "open"
            existing.acknowledged_at = None
            existing.acknowledged_by = None
        await db.delete(row)
        out["digest_conflicts_merged"] += 1

    return out
