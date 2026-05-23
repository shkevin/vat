"""Fetch Aikido container SBOMs and import into VAT for digest + merge signals.

Primary: GET /containers/{id}/licenses/export per container (rate-limited).

Optional: POST /containers/sbom/generate in batches when per-container export is empty
(https://apidocs.aikido.dev/reference/generatecontainersbom). Enable via
``VAT_AIKIDO_CONTAINER_SBOM_BULK_GENERATE=true``.
"""

from __future__ import annotations

import json
import logging
import inspect
from typing import Any, Callable

from sqlalchemy import or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.aikido import (
    _strip_tag_from_container_name,
    fetch_aikido_container_licenses_export,
    fetch_aikido_containers_sbom_bulk_generate,
)
from app.core.config import get_settings
from app.models.finding import Finding
from app.services.assets_service import _container_image_group_key
from app.services.container_asset_observations import upsert_digest_from_external_scan
from app.services.cyclonedx_identity import (
    extract_container_identity_from_cyclonedx,
    unwrap_cyclonedx_document,
)
from app.services.sbom import import_cyclonedx_sbom_like_ingest

logger = logging.getLogger(__name__)

_STAT_KEYS = (
    "containers_considered",
    "fetch_ok",
    "fetch_empty",
    "not_cyclonedx",
    "sbom_packages_created",
    "sbom_packages_updated",
    "findings_digest_backfill",
    "observed_tag_upserts",
    "import_errors",
    "bulk_batches_ok",
    "bulk_cyclonedx_docs",
    "bulk_unmapped_docs",
)


def _unwrap_nested_cdx_item(item: dict) -> dict | None:
    u = unwrap_cyclonedx_document(item)
    if u:
        return u
    for k in ("sbom", "bom", "cyclonedx", "document", "data", "licenses"):
        inner = item.get(k)
        if isinstance(inner, str) and inner.strip().startswith("{"):
            try:
                inner = json.loads(inner)
            except json.JSONDecodeError:
                continue
        if isinstance(inner, dict):
            u2 = unwrap_cyclonedx_document(inner)
            if u2:
                return u2
    return None


def iter_cyclonedx_from_aikido_bulk_sbom(raw: Any) -> list[tuple[str | None, dict]]:
    """
    Parse JSON from ``POST /containers/sbom/generate`` into
    ``(container_id_or_none, cyclonedx_document)`` pairs.
    """
    out: list[tuple[str | None, dict]] = []
    if raw is None:
        return out

    u = unwrap_cyclonedx_document(raw)
    if u:
        return [(None, u)]

    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            bid = (
                item.get("container_id")
                or item.get("containerId")
                or item.get("id")
            )
            bid_s = str(bid).strip() if bid is not None and str(bid).strip() else None
            doc = _unwrap_nested_cdx_item(item)
            if doc:
                out.append((bid_s, doc))
        return out

    if not isinstance(raw, dict):
        return out

    for key in ("sboms", "data", "containers", "results", "items"):
        block = raw.get(key)
        if isinstance(block, dict):
            doc = _unwrap_nested_cdx_item(block)
            if doc:
                out.append((None, doc))
            continue
        if not isinstance(block, list):
            continue
        for item in block:
            if not isinstance(item, dict):
                continue
            bid = (
                item.get("container_id")
                or item.get("containerId")
                or item.get("id")
                or item.get("container_repo_id")
                or item.get("containerRepoId")
            )
            bid_s = str(bid).strip() if bid is not None and str(bid).strip() else None
            doc = _unwrap_nested_cdx_item(item)
            if doc:
                out.append((bid_s, doc))

    return out


def _container_display_fields(c: dict) -> tuple[str | None, str | None, str]:
    """
    Return (asset_key without :tag, numeric id string, default tag from list payload).
    """
    cid = c.get("id")
    if cid is None:
        return None, None, "latest"
    sid = str(cid).strip()
    if not sid:
        return None, None, "latest"
    name = (
        c.get("name")
        or c.get("image")
        or c.get("repository_name")
        or c.get("repositoryName")
    )
    if name is None:
        return None, sid, "latest"
    name_str = str(name).strip()
    if not name_str:
        return None, sid, "latest"
    tag = (
        str(c.get("tag") or c.get("image_tag") or c.get("imageTag") or "latest").strip()
        or "latest"
    )
    name_no_tag = _strip_tag_from_container_name(name_str) or name_str
    return name_no_tag, sid, tag


def preferred_sbom_component_for_aikido_container(asset_key: str, c: dict) -> str:
    """
    Registry-style image ref for SBOM ``component`` / ``X-VAT-Source-Image`` parity
    with local scanner + Aikido findings (often ``docker.io/containers/images/...``).
    """
    ak = (asset_key or "").strip()
    for key in (
        "image",
        "repository",
        "repository_uri",
        "repositoryUri",
        "full_image",
        "fullImage",
        "registry_path",
        "registryPath",
    ):
        v = c.get(key)
        if isinstance(v, str):
            s = v.strip()
            if s and ("/" in s or "." in s):
                return _strip_tag_from_container_name(s) or s
    if ak.startswith("containers/") or ak.startswith("kamiwaza/"):
        return f"docker.io/{ak}"
    return ak


async def _ingest_container_sbom_cyclonedx(
    db: AsyncSession,
    c: dict,
    cdx: dict,
    stats: dict[str, int],
) -> None:
    asset_key, cid, list_tag = _container_display_fields(c)
    if not asset_key or not cid:
        return

    identity = extract_container_identity_from_cyclonedx(cdx)
    ingest_component = preferred_sbom_component_for_aikido_container(asset_key, c)
    ref_primary = (
        (identity.stamp_ref or ingest_component or asset_key).strip()[:256]
    )

    try:
        created, updated = await import_cyclonedx_sbom_like_ingest(
            db,
            cdx,
            source="Aikido",
            asset_override=asset_key,
            source_image_override=ref_primary,
            tenant_id=None,
        )
        stats["sbom_packages_created"] += created
        stats["sbom_packages_updated"] += updated
    except Exception as e:
        logger.warning(
            "Aikido SBOM import failed for container %s (%s): %s",
            cid,
            asset_key,
            str(e).split("\n")[0][:200],
        )
        stats["import_errors"] += 1
        return

    if identity.digest:
        tag = (identity.tag or list_tag or "latest").strip() or "latest"
        obs_asset_id = _container_image_group_key(asset_key, None)
        image_candidates = list(
            dict.fromkeys(
                x
                for x in (
                    asset_key,
                    ingest_component,
                    ref_primary,
                    obs_asset_id,
                )
                if (x or "").strip()
            )
        )
        try:
            res = await db.execute(
                update(Finding)
                .where(
                    Finding.source == "Aikido",
                    Finding.image_digest.is_(None),
                    or_(*[Finding.image == cand for cand in image_candidates]),
                )
                .values(image_digest=identity.digest)
            )
            stats["findings_digest_backfill"] += res.rowcount or 0
        except Exception as e:
            logger.debug("Digest backfill update failed: %s", e)

        try:
            await upsert_digest_from_external_scan(
                db,
                asset_id=obs_asset_id,
                tag=tag,
                digest=identity.digest,
            )
            stats["observed_tag_upserts"] += 1
        except Exception as e:
            logger.debug("Observed tag upsert failed: %s", e)

    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning("Aikido SBOM sync commit failed for container %s: %s", cid, e)
        stats["import_errors"] += 1


async def _sync_sboms_licenses_export(
    db: AsyncSession,
    creds: dict[str, Any],
    containers: list[Any],
    stats: dict[str, int],
    *,
    max_n: int,
    on_progress: Callable[[int, int, str], Any] | None = None,
) -> None:
    processed = 0
    total_candidates: list[Any] = []
    for c in containers or []:
        if not isinstance(c, dict):
            continue
        asset_key, cid, _list_tag = _container_display_fields(c)
        if asset_key and cid:
            total_candidates.append(c)
    total = min(len(total_candidates), max_n) if max_n > 0 else len(total_candidates)
    for c in containers or []:
        if not isinstance(c, dict):
            continue
        if max_n > 0 and processed >= max_n:
            break
        asset_key, cid, list_tag = _container_display_fields(c)
        if not asset_key or not cid:
            continue
        processed += 1
        stats["containers_considered"] += 1
        if on_progress:
            result = on_progress(processed, total, "Container SBOMs")
            if inspect.isawaitable(result):
                await result

        raw = await fetch_aikido_container_licenses_export(cid, credentials=creds)
        if raw is None:
            stats["fetch_empty"] += 1
            continue
        stats["fetch_ok"] += 1

        cdx = unwrap_cyclonedx_document(raw)
        if not cdx:
            stats["not_cyclonedx"] += 1
            continue

        await _ingest_container_sbom_cyclonedx(db, c, cdx, stats)


async def _sync_sboms_bulk_generate(
    db: AsyncSession,
    creds: dict[str, Any],
    containers: list[Any],
    stats: dict[str, int],
    *,
    max_n: int,
    batch_size: int,
    on_progress: Callable[[int, int, str], Any] | None = None,
) -> None:
    prepared: list[dict] = []
    for c in containers or []:
        if not isinstance(c, dict):
            continue
        asset_key, cid, _lt = _container_display_fields(c)
        if not asset_key or not cid:
            continue
        prepared.append(c)
        if max_n > 0 and len(prepared) >= max_n:
            break

    bs = max(1, batch_size)
    for i in range(0, len(prepared), bs):
        chunk = prepared[i : i + bs]
        stats["containers_considered"] += len(chunk)
        if on_progress:
            done = min(i + len(chunk), len(prepared))
            result = on_progress(done, len(prepared), "Container SBOMs")
            if inspect.isawaitable(result):
                await result
        ids = [c["id"] for c in chunk if c.get("id") is not None]
        if not ids:
            continue

        raw = await fetch_aikido_containers_sbom_bulk_generate(ids, credentials=creds)
        if raw is None:
            stats["fetch_empty"] += len(chunk)
            continue

        stats["fetch_ok"] += 1
        stats["bulk_batches_ok"] += 1
        pairs = iter_cyclonedx_from_aikido_bulk_sbom(raw)
        if not pairs:
            stats["not_cyclonedx"] += 1
            continue

        stats["bulk_cyclonedx_docs"] += len(pairs)
        chunk_by_id = {str(c.get("id")): c for c in chunk if c.get("id") is not None}

        for bid, doc in pairs:
            target: dict | None = None
            if bid is not None and bid in chunk_by_id:
                target = chunk_by_id[bid]
            elif bid is None and len(pairs) == 1 and len(chunk) == 1:
                target = chunk[0]
            else:
                stats["bulk_unmapped_docs"] += 1
                logger.debug(
                    "Bulk SBOM CycloneDX not mapped to container row "
                    "(batch_ids=%s doc_container_id=%r)",
                    list(chunk_by_id.keys()),
                    bid,
                )
                continue
            await _ingest_container_sbom_cyclonedx(db, target, doc, stats)


async def sync_aikido_container_sboms(
    db: AsyncSession,
    creds: dict[str, Any],
    containers: list[Any],
    *,
    source_id: str | None = None,
    on_progress: Callable[[int, int, str], Any] | None = None,
) -> dict[str, int]:
    """
    For each Aikido container with an id, fetch SBOM (licenses export or bulk generate),
    import CycloneDX packages, and backfill ``Finding.image_digest`` +
    ``asset_observed_tags.last_digest`` when a manifest digest is present in BOM metadata.

    Returns count dict for metrics/logging.
    """
    s = get_settings()
    if not s.aikido_container_sbom_sync:
        return {k: 0 for k in _STAT_KEYS}
    max_n = s.aikido_container_sbom_max_containers or 0

    stats = {k: 0 for k in _STAT_KEYS}

    if s.aikido_container_sbom_bulk_generate:
        await _sync_sboms_bulk_generate(
            db,
            creds,
            containers,
            stats,
            max_n=max_n,
            batch_size=s.aikido_container_sbom_bulk_batch_size,
            on_progress=on_progress,
        )
    else:
        await _sync_sboms_licenses_export(
            db, creds, containers, stats, max_n=max_n, on_progress=on_progress
        )

    logger.info(
        "Aikido container SBOM sync: considered=%d fetch_ok=%d bulk_batches=%d "
        "sbom_created=%d sbom_updated=%d digest_backfill_rows=%d",
        stats["containers_considered"],
        stats["fetch_ok"],
        stats["bulk_batches_ok"],
        stats["sbom_packages_created"],
        stats["sbom_packages_updated"],
        stats["findings_digest_backfill"],
    )
    return stats
