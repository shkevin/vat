"""Full Aikido sync: pull (bootstrap) + dashboard + backfill. Runs in background to avoid HTTP timeout."""

import hashlib
from collections import defaultdict
import logging
from typing import Any, Callable, Optional

from sqlalchemy import select, update

from app.adapters.aikido import (
    AikidoAdapter,
    _parse_repo_name_with_branch,
    _extract_branch_from_repo,
    _strip_tag_from_container_name,
    aikido_container_list_item_tags,
    fetch_aikido_code_repositories,
    fetch_aikido_containers,
    fetch_aikido_issues,
)
from app.core.database import async_session
from app.models.asset import Asset
from app.models.finding import Finding
from app.services.asset_resolver import infer_asset_kind
from app.services.audit_events import emit_audit_event
from app.services.container_asset_observations import ensure_container_tags_observed
from app.services.dedup import make_fingerprint
from app.services.ingest import _parse_iso_datetime, ingest_finding
from app.services.aikido_dashboard_sync import sync_aikido_dashboard

logger = logging.getLogger(__name__)


def _progress(
    on_progress: Optional[Callable[[int, int, str], None]],
    step: int,
    total: int,
    label: str,
) -> None:
    if on_progress:
        on_progress(step, total, label)


def _asset_key(name: str) -> str:
    """Build asset_key — name only. Branches are shown in asset page dropdown."""
    return (name or "").strip()


async def _ensure_asset_for_aikido_finding(session, finding: Finding) -> bool:
    """Create an ``Asset`` row for the finding's image when one is missing.

    Aikido's ``/containers`` endpoint enumerates only top-level container
    repositories, but ``/issues/export`` returns findings against many more
    images (variants like ``-dev``/``-fips``/``-cuda``). Without this
    backfill, those images show up only as findings and never as discrete
    assets in the UI. Mirrors the SBOM-side ``_ensure_sbom_asset_record``.
    """
    image = (getattr(finding, "image", None) or "").strip()
    if not image:
        return False
    existing = await session.get(Asset, image)
    if existing:
        return False
    inferred = infer_asset_kind(image, "aikido")
    kind = inferred if inferred in ("container", "repo") else "package"
    session.add(
        Asset(
            id=image,
            name=image,
            type=kind,
            source="Aikido",
            branch=getattr(finding, "branch", None),
            tag=None,
        )
    )
    return True


def _aikido_trace_id(source_id: str | None, issue: dict[str, Any]) -> str:
    """Create deterministic trace IDs for background Aikido sync audit events."""
    issue_id = str(issue.get("id") or issue.get("issue_id") or "unknown")
    seed = f"aikido-sync:{source_id or 'default'}:{issue_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def aikido_issue_trace_id(source_id: str | None, issue: dict[str, Any]) -> str:
    """Stable trace id for Aikido issue ingest (sync, webhook, bootstrap)."""
    return _aikido_trace_id(source_id, issue)


def _asset_trace_id(source_id: str | None, asset_type: str, asset_id: str) -> str:
    """Create deterministic trace IDs for Aikido asset lifecycle events."""
    seed = f"aikido-asset:{source_id or 'default'}:{asset_type}:{asset_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


async def run_full_sync(
    creds: dict,
    source_id: str | None = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, Any]:
    """
    Run pull (bootstrap) + dashboard sync + backfill. Uses its own DB sessions.
    Bootstrap order: create assets from repos/containers first, then ingest issues.
    Returns summary: {pull: {...}, dashboard: {...}, backfill: {...}}.
    on_progress(step, total, label) called at each step for UI progress bar.
    """
    result: dict[str, Any] = {"pull": {}, "dashboard": {}, "backfill": {}}
    total_steps = 18  # bootstrap(4) + dashboard(13) + backfill(1)
    step_num = 0

    # 1. Bootstrap: create assets first (repos, then containers), then ingest issues
    _progress(
        on_progress, step_num := step_num + 1, total_steps, "Bootstrap: Repositories"
    )
    repo_map: dict[int | str, str] = {}
    repo_id_to_name: dict[int | str, str] = {}
    repos: list = []
    containers: list = []
    assets_created = 0
    try:
        repos = (await fetch_aikido_code_repositories(credentials=creds)) or []
        async with async_session() as session:
            for r in repos or []:
                if not isinstance(r, dict) or r.get("id") is None:
                    continue
                rid = r["id"]
                branch = _extract_branch_from_repo(r)
                raw_name = str(r["name"]).strip() if r.get("name") else None
                if not raw_name:
                    continue
                base_name, branch_from_name = _parse_repo_name_with_branch(raw_name)
                branch = branch or branch_from_name
                name = base_name or raw_name
                key = _asset_key(name)
                if not key:
                    continue
                repo_map[rid] = branch or ""
                repo_map[str(rid)] = branch or ""
                repo_id_to_name[rid] = raw_name
                repo_id_to_name[str(rid)] = raw_name
                existing = await session.get(Asset, key)
                branch_val = (branch or "").strip() or None
                if not existing:
                    session.add(
                        Asset(
                            id=key,
                            name=name,
                            type="repo",
                            source="Aikido",
                            branch=branch_val,
                            tag=None,
                        )
                    )
                    assets_created += 1
                    await emit_audit_event(
                        session,
                        trace_id=_asset_trace_id(source_id, "repo", key),
                        event_type="asset.lifecycle.created",
                        actor_type="system",
                        source_id=source_id or "aikido",
                        parser_id="aikido",
                        asset_id=key,
                        decision_name="asset_lifecycle",
                        decision_reason_code="aikido_repository_discovered",
                        decision_confidence="high",
                        decision_result="created",
                        data={"asset_type": "repo", "branch": branch_val},
                    )
                elif branch_val and existing.branch != branch_val:
                    branches = {
                        b.strip()
                        for b in (existing.branch or "").split(",")
                        if b.strip()
                    }
                    branches.add(branch_val)
                    existing.branch = ",".join(sorted(branches))
            await session.commit()
    except Exception as e:
        logger.warning("Full sync: could not fetch/create repo assets: %s", e)

    _progress(
        on_progress, step_num := step_num + 1, total_steps, "Bootstrap: Containers"
    )
    try:
        containers = await fetch_aikido_containers(credentials=creds) or []
        tag_union_by_asset: dict[str, set[str]] = defaultdict(set)
        async with async_session() as session:
            for c in containers or []:
                if not isinstance(c, dict):
                    continue
                name = (
                    c.get("name")
                    or c.get("image")
                    or c.get("repository_name")
                    or c.get("repositoryName")
                    or c.get("id")
                )
                if name is None:
                    continue
                name_str = str(name).strip()
                if not name_str:
                    continue
                tag = (
                    str(c.get("tag") or c.get("image_tag") or "latest").strip()
                    or "latest"
                )
                # Strip :tag from asset name — tag is stored in Asset.tag for the dropdown
                name_no_tag = _strip_tag_from_container_name(name_str) or name_str
                asset_key = name_no_tag
                existing = await session.get(Asset, asset_key)
                if not existing:
                    session.add(
                        Asset(
                            id=asset_key,
                            name=name_no_tag,
                            type="container",
                            source="Aikido",
                            branch=None,
                            tag=tag,
                        )
                    )
                    assets_created += 1
                    await emit_audit_event(
                        session,
                        trace_id=_asset_trace_id(source_id, "container", asset_key),
                        event_type="asset.lifecycle.created",
                        actor_type="system",
                        source_id=source_id or "aikido",
                        parser_id="aikido",
                        asset_id=asset_key,
                        decision_name="asset_lifecycle",
                        decision_reason_code="aikido_container_discovered",
                        decision_confidence="high",
                        decision_result="created",
                        data={"asset_type": "container", "tag": tag},
                    )
                tag_list = aikido_container_list_item_tags(c) or (
                    [tag] if (tag or "").strip() else []
                )
                for t in tag_list:
                    if (t or "").strip():
                        tag_union_by_asset[asset_key].add(t.strip())
            for ak, ts in tag_union_by_asset.items():
                if ts:
                    await ensure_container_tags_observed(
                        session, asset_id=ak, tags=sorted(ts)
                    )
            await session.commit()
    except Exception as e:
        logger.warning("Full sync: could not fetch/create container assets: %s", e)

    _progress(on_progress, step_num := step_num + 1, total_steps, "Bootstrap: Issues")
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
    except Exception as e:
        logger.exception("Full sync: bootstrap fetch failed")
        result["pull"] = {"error": str(e)}
        return result

    _progress(on_progress, step_num := step_num + 1, total_steps, "Bootstrap: Ingest")
    # Build container_name -> id for Aikido dashboard links when container_repo_id is missing
    container_name_to_id: dict[str, str] = {}
    for c in containers or []:
        if not isinstance(c, dict) or c.get("id") is None:
            continue
        sid = str(c["id"])
        name = (
            c.get("name")
            or c.get("image")
            or c.get("repository_name")
            or c.get("repositoryName")
            or ""
        )
        if name:
            name_str = str(name).strip()
            name_no_tag = _strip_tag_from_container_name(name_str) or name_str
            container_name_to_id[name_str] = sid
            container_name_to_id[name_no_tag] = sid
    adapter = AikidoAdapter()
    created = 0
    merged = 0
    async with async_session() as session:
        # Cross-source dedup: ingest merges by fingerprint; no delete (preserves Trivy/manual findings)
        for raw in raw_issues:
            try:
                transformed = await adapter.to_vat_finding(
                    raw,
                    repo_map=repo_map,
                    repo_id_to_name=repo_id_to_name,
                    container_name_to_id=container_name_to_id,
                )
                trace_id = _aikido_trace_id(source_id, raw)
                resolved_asset = (
                    transformed.image or transformed.component or ""
                ).strip() or None
                await emit_audit_event(
                    session,
                    trace_id=trace_id,
                    event_type="asset.mapping.resolved",
                    actor_type="system",
                    source_id=source_id or "aikido",
                    parser_id="aikido",
                    asset_id=resolved_asset,
                    decision_name="asset_mapping",
                    decision_reason_code="aikido_payload_identity",
                    decision_confidence="high" if resolved_asset else "low",
                    decision_result="resolved" if resolved_asset else "unresolved",
                    data={"source_issue_id": str(raw.get("id") or "")},
                )
                finding, is_new = await ingest_finding(
                    session,
                    transformed,
                    source_name="Aikido",
                    tenant_id=None,
                    aikido_source_id=source_id,
                    trace_id=_aikido_trace_id(source_id, raw),
                    parser_id="aikido",
                )
                if await _ensure_asset_for_aikido_finding(session, finding):
                    assets_created += 1
                await emit_audit_event(
                    session,
                    trace_id=trace_id,
                    event_type="dedup.replay.new" if is_new else "dedup.replay.merged",
                    actor_type="system",
                    source_id=source_id or "aikido",
                    parser_id="aikido",
                    asset_id=resolved_asset,
                    finding_id=getattr(finding, "id", None),
                    decision_name="replay_dedup",
                    decision_reason_code="fingerprint_lookup",
                    decision_confidence="high",
                    decision_result="created" if is_new else "merged",
                    data={"source_issue_id": str(raw.get("id") or "")},
                )
                if is_new:
                    created += 1
                else:
                    merged += 1
            except Exception as e:
                await session.rollback()
                logger.warning(
                    "Full sync bootstrap failed for issue %s: %s",
                    raw.get("id", "?"),
                    str(e).split("\n")[0][:200],
                )
        # Backfill image=component for findings missing image
        await session.execute(
            update(Finding)
            .where(Finding.image.is_(None), Finding.component.isnot(None))
            .values(image=Finding.component)
        )
        await session.commit()

    result["pull"] = {
        "fetched": len(raw_issues),
        "created": created,
        "merged": merged,
        "assets_created": assets_created,
    }

    # 2. Dashboard sync (step_num is 3 after bootstrap)
    dashboard_base = step_num

    def _dashboard_progress(step: int, total: int, label: str) -> None:
        _progress(on_progress, dashboard_base + step, total_steps, label)

    try:
        async with async_session() as session:
            data = await sync_aikido_dashboard(
                creds,
                session,
                on_progress=_dashboard_progress,
                raw_issues_override=raw_issues,
                repo_map=repo_map,
                repo_id_to_name=repo_id_to_name,
                repos_override=repos,
                containers_override=containers,
                source_id=source_id,
            )
        result["dashboard"] = {
            "issues": len(data.get("issues", [])),
            "issueGroups": len(data.get("issueGroups", [])),
            "containers": len(data.get("containers", [])),
            "vms": len(data.get("vms", [])),
        }
    except Exception as e:
        logger.exception("Full sync: dashboard sync failed")
        result["dashboard"] = {"error": str(e)}
        return result

    # 3. Backfill first_detected_at and closed_at
    _progress(
        on_progress, total_steps, total_steps, "Backfill: first_detected_at, closed_at"
    )
    updated_fd = 0
    updated_ca = 0
    skipped_no_fd = 0
    skipped_has_fd = 0
    async with async_session() as session:
        for raw in raw_issues:
            try:
                transformed = await adapter.to_vat_finding(
                    raw,
                    repo_map=repo_map,
                    repo_id_to_name=repo_id_to_name,
                    container_name_to_id=container_name_to_id,
                )
                fd_str = getattr(transformed, "first_detected_at", None)
                fd_dt = _parse_iso_datetime(fd_str) if fd_str else None
                cd_str = getattr(transformed, "closed_at", None)
                cd_dt = _parse_iso_datetime(cd_str) if cd_str else None
                comp = transformed.component or transformed.component_base or ""
                img = transformed.image or ""
                branch = getattr(transformed, "branch", None) or ""
                tag = getattr(transformed, "tag", None) or ""
                fp = make_fingerprint(
                    transformed.cve_id, comp, image=img, branch=branch, tag=tag
                )
                r = await session.execute(
                    select(Finding).where(Finding.fingerprint_id == fp)
                )
                existing = r.scalar_one_or_none()
                if not existing:
                    continue
                changed = False
                if not fd_str:
                    skipped_no_fd += 1
                elif fd_dt and not existing.first_detected_at:
                    existing.first_detected_at = fd_dt
                    updated_fd += 1
                    changed = True
                elif existing.first_detected_at is not None:
                    skipped_has_fd += 1
                if cd_dt and not existing.closed_at:
                    existing.closed_at = cd_dt
                    updated_ca += 1
                    changed = True
                if changed:
                    await session.commit()
            except Exception as e:
                await session.rollback()
                logger.warning(
                    "Full sync backfill failed for issue %s: %s",
                    raw.get("id", "?"),
                    str(e).split("\n")[0][:200],
                )

    result["backfill"] = {
        "updated_first_detected": updated_fd,
        "updated_closed_at": updated_ca,
        "skipped_no_first_detected": skipped_no_fd,
        "skipped_already_has": skipped_has_fd,
    }
    logger.info(
        "Full sync complete: pull %d/%d/%d, dashboard %d issues, backfill fd=%d ca=%d",
        len(raw_issues),
        created,
        merged,
        result["dashboard"].get("issues", 0),
        result["backfill"].get("updated_first_detected", 0),
        result["backfill"].get("updated_closed_at", 0),
    )
    return result
