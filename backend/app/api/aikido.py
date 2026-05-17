"""Aikido bootstrap API — one-time GET /issues/export to seed existing findings. PRD §8.4.1."""

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.aikido import (
    AikidoAdapter,
    _extract_branch_from_repo,
    _parse_repo_name_with_branch,
    _strip_tag_from_container_name,
    fetch_aikido_code_repositories,
    fetch_aikido_containers,
    fetch_aikido_issues,
)
from app.api.settings import (
    get_aikido_credentials,
    has_aikido_source_on_canvas,
)
from app.core.auth import require_admin, require_reviewer
from app.core.database import async_session, get_db
from app.schemas.auth import UserContext
from app.models.finding import Finding
from app.models.settings_model import SettingsKV
from app.services.ingest import ingest_finding, _parse_iso_datetime
from app.services.dedup import make_fingerprint
from app.services.aikido_dashboard_sync import (
    get_aikido_dashboard_cached,
    sync_aikido_dashboard,
)
from app.services.aikido_full_sync import aikido_issue_trace_id, run_full_sync

router = APIRouter()
logger = logging.getLogger(__name__)


# Sync status per source_id for progress bar persistence across page refresh (in-memory, per process).
# Each Aikido source node tracks its own sync progress independently.
def _default_slot() -> dict:
    return {
        "status": "idle",
        "message": None,
        "started_at": None,
        "step": 0,
        "total": 0,
        "label": None,
        "source_id": None,
    }


_aikido_sync_status_by_source: dict[str, dict] = {}
AIKIDO_SYNC_STATUS_PREFIX = "aikido_sync_status:"


def _slot_for(source_id: str | None) -> dict:
    """Get or create sync status slot for the given source_id."""
    key = source_id if source_id else "default"
    if key not in _aikido_sync_status_by_source:
        _aikido_sync_status_by_source[key] = _default_slot()
    return _aikido_sync_status_by_source[key]


def _sync_status_key(source_id: str | None) -> str:
    sid = source_id if source_id else "default"
    return f"{AIKIDO_SYNC_STATUS_PREFIX}{sid}"


def _slot_snapshot(slot: dict) -> dict:
    return {
        "status": slot.get("status", "idle"),
        "message": slot.get("message"),
        "started_at": slot.get("started_at"),
        "step": int(slot.get("step", 0) or 0),
        "total": int(slot.get("total", 0) or 0),
        "label": slot.get("label"),
        "source_id": slot.get("source_id"),
    }


async def _upsert_sync_status(db: AsyncSession, source_id: str | None, slot: dict) -> None:
    key = _sync_status_key(source_id)
    snapshot = _slot_snapshot(slot)
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row:
        row.value = snapshot
        row.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        db.add(
            SettingsKV(
                key=key,
                value=snapshot,
                updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
        )


async def _persist_sync_status(source_id: str | None, slot: dict) -> None:
    async with async_session() as session:
        await _upsert_sync_status(session, source_id, slot)
        await session.commit()


async def _read_persisted_sync_status(
    db: AsyncSession, source_id: str | None
) -> dict | None:
    key = _sync_status_key(source_id)
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if not row or not isinstance(row.value, dict):
        return None
    return row.value


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aikido_configured(creds: dict) -> bool:
    """True if OAuth (client_id+client_secret) is configured."""
    return bool(creds.get("client_id") and creds.get("client_secret"))


@router.get("/debug-sample")
async def aikido_debug_sample(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Debug: return keys/structure of first raw Aikido issue (no sensitive data).
    Use to verify field names for asset extraction (code_repo_name, container_repo_name, etc.).
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(status_code=503, detail="Aikido not configured")
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
    except Exception as e:
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e
    if not raw_issues:
        return {"message": "No issues from Aikido", "keys": []}
    first = raw_issues[0]
    if not isinstance(first, dict):
        return {"message": "First issue is not a dict", "type": str(type(first))}
    # Return top-level keys and sample values (truncated) for debugging
    keys_info = {}
    for k, v in first.items():
        if isinstance(v, (str, int, float, bool, type(None))):
            keys_info[k] = str(v)[:80] if v else v
        elif isinstance(v, list):
            keys_info[k] = f"[list len={len(v)}]"
            if v and isinstance(v[0], dict):
                keys_info[f"{k}[0].keys"] = list(v[0].keys())
                # Show url/link fields in first location
                for url_key in ("url", "link", "file_url", "html_url", "web_url"):
                    if url_key in v[0]:
                        keys_info[f"{k}[0].{url_key}"] = v[0][url_key]
        elif isinstance(v, dict):
            keys_info[f"{k}.keys"] = list(v.keys())
            for url_key in ("url", "link", "html_url", "web_url", "repository_url"):
                if url_key in v:
                    keys_info[f"{k}.{url_key}"] = v[url_key]
        else:
            keys_info[k] = str(type(v))
    # Explicitly collect any url-like fields for repo/file linking
    url_fields = {}
    for k, v in first.items():
        if "url" in k.lower() or "link" in k.lower():
            if isinstance(v, str) and v.startswith("http"):
                url_fields[k] = v[:120]
    # Date fields for first_detected_at debugging (report trend alignment)
    date_fields = {
        k: v
        for k, v in first.items()
        if isinstance(v, (str, int, float))
        and any(
            d in k.lower()
            for d in ("detect", "created", "seen", "discover", "timestamp", "date")
        )
    }
    return {
        "message": "Sample from first issue",
        "keys": list(first.keys()),
        "sample": keys_info,
        "url_fields": url_fields,
        "date_fields": date_fields,
    }


@router.get("/debug-branches")
async def aikido_debug_branches(
    repo: str = "kamiwaza",
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Debug: fetch Aikido issues and show branch-related fields.
    Use ?repo=kamiwaza to filter. Shows what Aikido actually returns for multi-branch.
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(status_code=503, detail="Aikido not configured")
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
    except Exception as e:
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e

    repo_filter = repo.lower()

    def _matches_repo(issue: dict) -> bool:
        name = str(
            issue.get("code_repo_name") or issue.get("codeRepoName") or ""
        ).lower()
        locs = issue.get("locations") or issue.get("instances") or []
        for loc in locs if isinstance(locs, list) else []:
            if isinstance(loc, dict):
                n = str(loc.get("name") or loc.get("code_repo_name") or "").lower()
                if repo_filter in n:
                    return True
        return repo_filter in name

    samples = []
    branches_seen = set()
    repo_names_seen = set()

    for i, raw in enumerate(raw_issues):
        if not isinstance(raw, dict):
            continue
        if not _matches_repo(raw):
            continue
        repo_name = raw.get("code_repo_name") or raw.get("codeRepoName") or ""
        locs = (
            raw.get("locations")
            or raw.get("instances")
            or raw.get("locations_list")
            or []
        )
        repo_names_seen.add(repo_name)

        # Extract all possible branch-related fields
        branch_data = {
            "id": raw.get("id"),
            "code_repo_name": raw.get("code_repo_name") or raw.get("codeRepoName"),
            "branch": raw.get("branch"),
            "git_branch": raw.get("git_branch"),
            "code_repo_branch": raw.get("code_repo_branch"),
            "scanned_branch": raw.get("scanned_branch"),
            "ref": raw.get("ref"),
            "code_repository": raw.get("code_repository") or raw.get("codeRepository"),
            "repository": raw.get("repository"),
            "locations": locs[:2] if isinstance(locs, list) else locs,
            "top_level_keys": [
                k for k in raw.keys() if "branch" in k.lower() or "repo" in k.lower()
            ],
        }
        if isinstance(locs, list) and locs and isinstance(locs[0], dict):
            loc0 = locs[0]
            branch_data["locations[0]"] = {
                k: v
                for k, v in loc0.items()
                if "branch" in k.lower() or "name" in k.lower() or "type" in k.lower()
            }
            b = (
                loc0.get("branch")
                or loc0.get("scanned_branch")
                or loc0.get("git_branch")
            )
            if b:
                branches_seen.add(str(b))

        for k in ("branch", "git_branch", "code_repo_branch", "scanned_branch"):
            v = raw.get(k)
            if v:
                branches_seen.add(str(v))

        samples.append(branch_data)
        if len(samples) >= 15:
            break

    return {
        "repo_filter": repo_filter,
        "total_issues_from_aikido": len(raw_issues),
        "matching_issues": len(samples),
        "branches_seen": sorted(branches_seen),
        "repo_names_seen": sorted(repo_names_seen),
        "samples": samples[:5],
    }


@router.get("/debug-branch-mapping")
async def aikido_debug_branch_mapping(
    repo: str = "kamiwaza",
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Debug: verify code_repo_id -> branch mapping for issues.
    Shows counts per (code_repo_id, branch) for matching issues.
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(status_code=503, detail="Aikido not configured")
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
        repos = await fetch_aikido_code_repositories(credentials=creds)
    except Exception as e:
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e

    repo_map: dict = {}
    for r in repos or []:
        if isinstance(r, dict) and r.get("id") is not None and r.get("branch"):
            rid = r["id"]
            repo_map[rid] = str(r["branch"]).strip()
            repo_map[str(rid)] = str(r["branch"]).strip()

    repo_filter = repo.lower()
    counts: dict[tuple, int] = {}
    samples_by_key: dict[tuple, list] = {}

    for raw in raw_issues:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("code_repo_name") or raw.get("codeRepoName") or "").lower()
        if repo_filter not in name:
            continue
        repo_id = raw.get("code_repo_id") or raw.get("codeRepoId")
        branch = None
        if repo_id is not None:
            branch = repo_map.get(repo_id) or repo_map.get(str(repo_id))
            if not branch:
                try:
                    branch = repo_map.get(int(repo_id))
                except (TypeError, ValueError):
                    pass
        if not branch:
            branch = "(unmapped)"
        key = (str(repo_id), branch)
        counts[key] = counts.get(key, 0) + 1
        if key not in samples_by_key:
            samples_by_key[key] = []
        if len(samples_by_key[key]) < 2:
            samples_by_key[key].append(
                {
                    "id": raw.get("id"),
                    "code_repo_id": repo_id,
                    "code_repo_name": raw.get("code_repo_name"),
                    "title": (
                        str(
                            raw.get("title")
                            or raw.get("rule")
                            or raw.get("affected_package")
                            or raw.get("cve_id")
                            or ""
                        )
                    )[:80],
                }
            )

    kamiwaza_repo_ids = {1211371, 1489682, 1544101}
    repo_map_kamiwaza = {
        str(k): v
        for k, v in repo_map.items()
        if isinstance(k, int) and k in kamiwaza_repo_ids
    }
    return {
        "repo_filter": repo_filter,
        "repo_map_kamiwaza": repo_map_kamiwaza,
        "counts_by_code_repo_id_and_branch": [
            {"code_repo_id": k[0], "branch": k[1], "count": v}
            for k, v in sorted(counts.items())
        ],
        "samples": {f"{k[0]}_{k[1]}": v for k, v in samples_by_key.items()},
    }


@router.get("/debug-repos")
async def aikido_debug_repos(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Debug: fetch Aikido code repositories (GET /repositories/code).
    Shows id, name, branch per repo to map code_repo_id -> branch for issues.
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(status_code=503, detail="Aikido not configured")
    try:
        repos = await fetch_aikido_code_repositories(credentials=creds)
    except Exception as e:
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e
    if not repos:
        return {"message": "No code repositories", "repos": []}
    # Filter kamiwaza-related and show full structure of first few
    kamiwaza_repos = [
        r
        for r in repos
        if isinstance(r, dict) and "kamiwaza" in str(r.get("name", "")).lower()
    ]
    sample = kamiwaza_repos[:10] if kamiwaza_repos else repos[:5]
    first_keys = list(repos[0].keys()) if repos and isinstance(repos[0], dict) else []
    return {
        "total_repos": len(repos),
        "kamiwaza_count": len(kamiwaza_repos),
        "first_repo_keys": first_keys,
        "kamiwaza_repos": sample,
    }


@router.get("/debug-db")
async def aikido_debug_db(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Debug: return findings count and sample image/component from DB.
    Use to verify asset grouping data exists after bootstrap.
    """
    r = await db.execute(
        select(
            Finding.id,
            Finding.image,
            Finding.component,
            Finding.branch,
            Finding.tenant_id,
        ).limit(10)
    )
    sample = [
        {
            "id": row[0],
            "image": row[1],
            "component": row[2],
            "branch": row[3],
            "tenant_id": row[4],
        }
        for row in r
    ]
    count_r = await db.execute(select(func.count(Finding.id)))
    total = count_r.scalar() or 0
    with_img = await db.execute(
        select(func.count(Finding.id)).where(Finding.image.isnot(None))
    )
    with_comp = await db.execute(
        select(func.count(Finding.id)).where(Finding.component.isnot(None))
    )
    return {
        "total_findings": total,
        "with_image": with_img.scalar() or 0,
        "with_component": with_comp.scalar() or 0,
        "sample": sample,
    }


@router.get("/sync-status")
async def aikido_sync_status(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
    source_id: str | None = None,
):
    """Return current Aikido sync status for the given source_id. Each source tracks independently."""
    slot = _slot_for(source_id)
    persisted = await _read_persisted_sync_status(db, source_id)
    current = persisted if persisted else _slot_snapshot(slot)
    last_synced_at = None
    cached = await get_aikido_dashboard_cached(db, source_id)
    if cached and isinstance(cached.get("fetchedAt"), str):
        last_synced_at = cached["fetchedAt"]
    return {
        "status": current.get("status", "idle"),
        "message": current.get("message"),
        "started_at": current.get("started_at"),
        "step": current.get("step", 0),
        "total": current.get("total", 0),
        "label": current.get("label"),
        "source_id": current.get("source_id"),
        "lastSyncedAt": last_synced_at,
    }


@router.post("/sync")
async def aikido_sync(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
    source_id: str | None = Body(None, embed=True),
):
    """
    Start full sync (pull + dashboard + backfill) in background. Returns immediately to avoid proxy timeout.
    Sync may take several minutes. Progress bar persists across page refresh via GET /sync-status.
    source_id scopes the progress bar to the node that initiated sync (for multiple Aikido sources).
    """
    if not source_id:
        raise HTTPException(
            status_code=400, detail="source_id is required for Aikido sync"
        )
    creds = await get_aikido_credentials(db, source_id)
    if not _aikido_configured(creds):
        raise HTTPException(
            status_code=503,
            detail="Aikido not configured for this source. Set client_id, client_secret, and region (OAuth) in Settings.",
        )
    if not await has_aikido_source_on_canvas(db):
        raise HTTPException(
            status_code=400,
            detail="Add the Aikido integration to the canvas first to enable sync.",
        )

    msg = "Sync running in background. This may take a few minutes. Refresh the page or check the Report tab when complete."
    slot = _slot_for(source_id)
    slot["status"] = "running"
    slot["message"] = msg
    slot["started_at"] = _now()
    slot["step"] = 0
    slot["total"] = 0
    slot["label"] = None
    slot["source_id"] = source_id
    await _upsert_sync_status(db, source_id, slot)
    await db.commit()

    def _on_progress(step: int, total: int, label: str) -> None:
        slot["step"] = step
        slot["total"] = total
        slot["label"] = label
        asyncio.create_task(_persist_sync_status(source_id, slot))

    async def _bg():
        try:
            result = await run_full_sync(
                creds, source_id=source_id, on_progress=_on_progress
            )
            pull_err = result.get("pull", {}).get("error")
            dash_err = result.get("dashboard", {}).get("error")
            if pull_err or dash_err:
                err_msg = pull_err or dash_err or "Sync failed"
                logger.error("Background Aikido sync failed: %s", err_msg)
                slot["status"] = "error"
                slot["message"] = str(err_msg)[:500]
            else:
                slot["status"] = "success"
                slot["message"] = (
                    "Sync complete. Refresh the Report tab to see updated data."
                )
            await _persist_sync_status(source_id, slot)
        except Exception as e:
            logger.exception("Background Aikido sync failed: %s", e)
            slot["status"] = "error"
            slot["message"] = str(e)[:500]
            await _persist_sync_status(source_id, slot)

    asyncio.create_task(_bg())
    return {
        "status": "started",
        "message": msg,
    }


@router.post("/sync-dashboard")
async def aikido_sync_dashboard(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
    source_id: str | None = Body(None, embed=True),
):
    """
    Sync data from Aikido to VAT (issues, groups, containers, VMs, activity log, CI scans, etc.).
    Excludes teams and compliance. source_id scopes to per-source credentials and cache.
    """
    if not source_id:
        raise HTTPException(status_code=400, detail="source_id is required")
    creds = await get_aikido_credentials(db, source_id)
    if not _aikido_configured(creds):
        raise HTTPException(
            status_code=503,
            detail="Aikido not configured for this source. Set client_id, client_secret, and region (OAuth) in Settings.",
        )
    if not await has_aikido_source_on_canvas(db):
        raise HTTPException(
            status_code=400,
            detail="Add the Aikido integration to the canvas first to enable sync.",
        )
    try:
        data = await sync_aikido_dashboard(creds, db, source_id=source_id)
    except Exception as e:
        logger.exception("Aikido sync failed")
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e
    return {
        "message": "Dashboard sync complete",
        "issues": len(data.get("issues", [])),
        "issueGroups": len(data.get("issueGroups", [])),
        "containers": len(data.get("containers", [])),
        "vms": len(data.get("vms", [])),
        "fetchedAt": data.get("fetchedAt"),
        "containerSbomSync": data.get("containerSbomSync"),
    }


@router.get("/dashboard-data")
async def aikido_dashboard_data(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_reviewer),
    source_id: str | None = None,
):
    """Return cached Aikido data synced to VAT. Run POST /aikido/sync or /aikido/sync-dashboard first. source_id scopes to per-source cache."""
    data = await get_aikido_dashboard_cached(db, source_id)
    if not data:
        raise HTTPException(
            status_code=404,
            detail="No Aikido data synced yet. Run POST /aikido/sync-dashboard first.",
        )
    return data


@router.post("/backfill-first-detected")
async def aikido_backfill_first_detected(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Backfill first_detected_at and closed_at for existing findings from Aikido.
    Fetches issues from Aikido, matches by fingerprint, updates findings that have no first_detected_at or closed_at.
    Use to fix report trend alignment with vulnerability-dashboard.
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(
            status_code=503,
            detail="Aikido not configured. Set client_id, client_secret, and region (OAuth) in Settings.",
        )
    if not await has_aikido_source_on_canvas(db):
        raise HTTPException(
            status_code=400,
            detail="Add the Aikido integration to the canvas first to enable sync.",
        )
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
    except Exception as e:
        logger.exception("Aikido backfill fetch failed")
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e

    repo_map: dict = {}
    repo_id_to_name: dict = {}
    try:
        repos = await fetch_aikido_code_repositories(credentials=creds)
        for r in repos or []:
            if isinstance(r, dict) and r.get("id") is not None:
                rid = r["id"]
                branch = _extract_branch_from_repo(r)
                if not branch and r.get("name"):
                    _, branch = _parse_repo_name_with_branch(str(r["name"]))
                if branch:
                    repo_map[rid] = branch
                    repo_map[str(rid)] = branch
                if r.get("name"):
                    repo_id_to_name[rid] = str(r["name"]).strip()
                    repo_id_to_name[str(rid)] = str(r["name"]).strip()
    except Exception as e:
        logger.warning("Could not fetch Aikido repos for branch/name mapping: %s", e)

    adapter = AikidoAdapter()
    updated_fd = 0
    updated_ca = 0
    skipped_no_fd = 0
    skipped_has_fd = 0

    async with async_session() as session:
        for raw in raw_issues:
            try:
                transformed = await adapter.to_vat_finding(
                    raw, repo_map=repo_map, repo_id_to_name=repo_id_to_name
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

                result = await session.execute(
                    select(Finding).where(Finding.fingerprint_id == fp)
                )
                existing = result.scalar_one_or_none()
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
                    "Backfill failed for issue %s: %s",
                    raw.get("id", "?"),
                    str(e).split("\n")[0][:200] if str(e) else type(e).__name__,
                )

    return {
        "message": "Backfill complete",
        "fetched": len(raw_issues),
        "updated_first_detected": updated_fd,
        "updated_closed_at": updated_ca,
        "skipped_no_first_detected": skipped_no_fd,
        "skipped_already_has": skipped_has_fd,
    }


@router.post("/bootstrap")
async def aikido_bootstrap(
    create_tracker_issues: bool = False,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    One-time bootstrap: fetch all issues from Aikido GET /issues/export and ingest.
    PRD §8.4.1. Use create_tracker_issues=true to also create tracker issues (Linear, Jira, etc.) for new findings.
    Requires OAuth (client_id+client_secret+region) in settings.
    """
    creds = await get_aikido_credentials(db)
    if not _aikido_configured(creds):
        raise HTTPException(
            status_code=503,
            detail="Aikido not configured. Set client_id, client_secret, and region (OAuth) in Settings.",
        )
    if not await has_aikido_source_on_canvas(db):
        raise HTTPException(
            status_code=400,
            detail="Add the Aikido integration to the canvas first to enable sync.",
        )
    try:
        raw_issues = await fetch_aikido_issues(credentials=creds)
    except Exception as e:
        logger.exception("Aikido bootstrap fetch failed")
        logger.exception("aikido upstream call failed"); raise HTTPException(status_code=502, detail="aikido upstream error") from e

    # Keep findings global (tenant_id=None) so they're visible to all users/tenants
    tenant_id: str | None = None

    # Build code_repo_id -> branch and code_repo_id -> name from Aikido repos
    repo_map: dict[int | str, str] = {}
    repo_id_to_name: dict[int | str, str] = {}
    try:
        repos = await fetch_aikido_code_repositories(credentials=creds)
        for r in repos or []:
            if isinstance(r, dict) and r.get("id") is not None:
                rid = r["id"]
                branch = _extract_branch_from_repo(r)
                if not branch and r.get("name"):
                    _, branch = _parse_repo_name_with_branch(str(r["name"]))
                if branch:
                    repo_map[rid] = branch
                    repo_map[str(rid)] = branch
                if r.get("name"):
                    repo_id_to_name[rid] = str(r["name"]).strip()
                    repo_id_to_name[str(rid)] = str(r["name"]).strip()
    except Exception as e:
        logger.warning("Could not fetch Aikido repos for branch/name mapping: %s", e)

    container_name_to_id: dict[str, str] = {}
    try:
        containers = await fetch_aikido_containers(credentials=creds) or []
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
    except Exception as e:
        logger.warning("Could not fetch Aikido containers for link mapping: %s", e)

    adapter = AikidoAdapter()
    created = 0
    merged = 0

    async with async_session() as session:
        # Cross-source dedup: ingest merges by fingerprint; no delete (preserves manual findings)
        for raw in raw_issues:
            try:
                # Adapter accepts raw issue or { issue: {...} }; ingest expects VAT format
                transformed = await adapter.to_vat_finding(
                    raw,
                    repo_map=repo_map,
                    repo_id_to_name=repo_id_to_name,
                    container_name_to_id=container_name_to_id,
                )

                finding, is_new = await ingest_finding(
                    session,
                    transformed,
                    source_name="Aikido",
                    tenant_id=tenant_id,
                    auto_sync_to_tracker=create_tracker_issues,
                    trace_id=aikido_issue_trace_id(source_id, raw),
                    parser_id="aikido",
                )
                if is_new:
                    created += 1
                elif not is_new:
                    merged += 1
            except Exception as e:
                await session.rollback()
                msg = str(e).split("\n")[0][:200] if str(e) else type(e).__name__
                logger.warning(
                    "Bootstrap ingest failed for issue %s: %s", raw.get("id", "?"), msg
                )
                logger.debug(
                    "Bootstrap ingest failed for issue %s",
                    raw.get("id", "?"),
                    exc_info=True,
                )

    # Backfill: set image=component for findings with no image (fixes old data)
    # Also clear tenant_id on Aikido findings so they're visible to all users/tenants
    async with async_session() as session:
        await session.execute(
            update(Finding)
            .where(Finding.image.is_(None), Finding.component.isnot(None))
            .values(image=Finding.component)
        )
        await session.execute(
            update(Finding).where(Finding.source == "Aikido").values(tenant_id=None)
        )
        await session.commit()

    # Debug: count findings with image/component for asset grouping
    async with async_session() as session:
        r = await session.execute(
            select(
                Finding.id,
                Finding.image,
                Finding.component,
                Finding.tenant_id,
            ).limit(10)
        )
        sample = [
            {"id": row[0], "image": row[1], "component": row[2], "tenant_id": row[3]}
            for row in r
        ]
        count_r = await session.execute(select(func.count(Finding.id)))
        total = count_r.scalar() or 0
        with_img = await session.execute(
            select(func.count(Finding.id)).where(Finding.image.isnot(None))
        )
        with_comp = await session.execute(
            select(func.count(Finding.id)).where(Finding.component.isnot(None))
        )

    return {
        "message": "Aikido bootstrap complete",
        "fetched": len(raw_issues),
        "created": created,
        "merged": merged,
        "debug": {
            "total_findings": total,
            "with_image": with_img.scalar() or 0,
            "with_component": with_comp.scalar() or 0,
            "sample": sample,
        },
    }
