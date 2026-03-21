"""Sync data from Aikido to VAT — issues, groups, containers, VMs, activity, CI scans, etc."""

import logging
from datetime import datetime, timezone


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


from typing import Any, Callable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.adapters.aikido import (
    _extract_asset_name,
    _extract_branch,
    _strip_tag_from_container_name,
    _extract_branch_from_repo,
    _parse_repo_name_with_branch,
    fetch_aikido_code_repositories,
    fetch_aikido_containers,
    fetch_aikido_issue_counts,
    fetch_aikido_issues,
    fetch_aikido_task_projects,
    fetch_aikido_virtual_machines,
    fetch_aikido_workspace,
)
from app.services.sync_service import sync_aikido_tracker_links
from app.models.settings_model import SettingsKV
from app.services.aikido_export import export_aikido_sync_to_excel

logger = logging.getLogger(__name__)

AIKIDO_DASHBOARD_KEY = "aikido_dashboard_data"
AIKIDO_DASHBOARD_PREFIX = "aikido_dashboard_data:"


def _dashboard_key(source_id: str | None) -> str:
    """Settings key for Aikido dashboard cache. Per-source when source_id given."""
    return (
        f"{AIKIDO_DASHBOARD_PREFIX}{source_id}" if source_id else AIKIDO_DASHBOARD_KEY
    )


def _ts_to_iso(ts: Any) -> str:
    """Convert Unix timestamp (seconds or ms) or ISO string to ISO string."""
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str) and ts.strip():
        return ts.strip()
    if isinstance(ts, (int, float)):
        t = float(ts)
        if t > 1e12:
            t = t / 1000
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _aikido_status_to_vat(
    raw_status: str, ignored_at: Any = None, closed_at: Any = None
) -> str:
    """Map Aikido status to VAT display. Must match adapter logic exactly for infallible validation.
    Order: ignored -> Suppressed; closed_at or status closed/resolved -> Resolved; else Open."""
    if ignored_at:
        return "Suppressed"
    s = str(raw_status or "open").lower()
    if s in ("ignored", "auto_ignored", "suppressed"):
        return "Suppressed"
    if closed_at or s in ("closed", "resolved"):
        return "Resolved"
    return "Open"


def _is_container_path(name: str) -> bool:
    """True if name is a container registry path (e.g. containers/images/etcd, kamiwaza/images/vllm).
    Aikido container names always have /images/<container> — never bare 'images'."""
    if not name or not isinstance(name, str):
        return False
    parts = name.strip().split("/")
    return len(parts) >= 3 and parts[-2].lower() == "images"


def _normalize_issue(
    raw: dict,
    repo_map: Optional[dict] = None,
    repo_id_to_name: Optional[dict] = None,
) -> dict:
    """Normalize Aikido issue to report format (first_detected_at as ISO string).
    Uses same asset extraction as adapter so Excel repository matches VAT image for validation.
    repo_map: optional {code_repo_id: branch} to enrich branch when Aikido export omits it.
    repo_id_to_name: optional {code_repo_id: name} for code repos when code_repo_name is missing."""
    fd = raw.get("first_detected_at") or raw.get("firstDetectedAt")
    ld = raw.get("last_detected_at") or raw.get("lastDetectedAt") or fd
    closed = raw.get("closed_at") or raw.get("closedAt")
    raw_asset = _extract_asset_name(raw)
    is_container = bool(raw.get("container_repo_name") or raw.get("containerRepoName"))
    if raw_asset and is_container and _is_container_path(raw_asset):
        # Container paths: containers/images/etcd, kamiwaza/images/vllm — use full path as-is.
        # Strip :tag from asset name — tag is stored separately.
        repo_base, branch_from_name = _strip_tag_from_container_name(raw_asset), None
    elif raw_asset:
        repo_base, branch_from_name = _parse_repo_name_with_branch(raw_asset)
    else:
        fallback_repo = (
            raw.get("container_repo_name")
            or raw.get("containerRepoName")
            or raw.get("code_repo_name")
            or raw.get("codeRepoName")
            or raw.get("repository")
        )
        if fallback_repo:
            fallback_str = str(fallback_repo).strip()
            if is_container and _is_container_path(fallback_str):
                repo_base, branch_from_name = (
                    _strip_tag_from_container_name(fallback_str),
                    None,
                )
            else:
                repo_base, branch_from_name = _parse_repo_name_with_branch(fallback_str)
        else:
            # Code repo with code_repo_id but no code_repo_name — use repo_id_to_name (kamiwaza is repo, not package)
            repo_id = raw.get("code_repo_id") or raw.get("codeRepoId")
            if repo_id is not None and repo_id_to_name:
                repo_name = repo_id_to_name.get(repo_id) or repo_id_to_name.get(
                    str(repo_id)
                )
                if repo_name:
                    repo_base, branch_from_name = _parse_repo_name_with_branch(
                        str(repo_name)
                    )
                else:
                    repo_base, branch_from_name = (None, None)
            else:
                repo_base, branch_from_name = (None, None)
    sev = str(raw.get("severity") or "unknown").lower()
    sev_score = raw.get("severity_score")
    if sev_score is None:
        sev_score = 5
    if isinstance(sev_score, (int, float)) and sev_score > 10:
        sev_score = round(sev_score / 10 * 10) / 10
    raw_status = str(raw.get("status") or "open").lower()
    ignored_at = raw.get("ignored_at") or raw.get("ignoredAt")
    closed_at = raw.get("closed_at") or raw.get("closedAt")
    # Aikido uses separate repos per branch; no branch field in export. Encode as "repo (branch)" in repository.
    branch_val = (
        raw.get("branch")
        or raw.get("git_branch")
        or (_extract_branch(raw, repo_map) if repo_map else branch_from_name)
    )
    repo = str(repo_base) if repo_base else None
    if repo and branch_val:
        repo = f"{repo} ({branch_val})"
    return {
        "issue_id": raw.get("id") or raw.get("issue_id") or 0,
        "issue_group_id": raw.get("group_id") or raw.get("issue_group_id") or 0,
        "first_detected_at": _ts_to_iso(fd),
        "last_detected_at": _ts_to_iso(ld),
        "closed_at": _ts_to_iso(closed) if closed else None,
        "repository": repo,
        "severity": sev,
        "severity_score": float(sev_score) if sev_score is not None else 5,
        "status": raw_status,
        "vat_status": _aikido_status_to_vat(
            raw_status, ignored_at=ignored_at, closed_at=closed_at
        ),
        "title": raw.get("rule")
        or raw.get("title")
        or raw.get("affected_package")
        or "Unknown",
        "cve_id": raw.get("cve_id") or raw.get("cveId"),
        "description": raw.get("description"),
        "affected_package": raw.get("affected_package") or raw.get("affectedPackage"),
        "affected_version": raw.get("installed_version")
        or raw.get("installedVersion")
        or raw.get("affected_version"),
        "fixed_version": (raw.get("patched_versions") or [None])[0]
        if isinstance(raw.get("patched_versions"), list)
        else raw.get("fixed_version"),
        "scanner_type": raw.get("type") or raw.get("scanner_type") or "unknown",
    }


def _normalize_issue_group(raw: dict) -> dict:
    """Normalize Aikido issue group to report format."""
    fd = (
        raw.get("first_detected_at")
        or raw.get("firstDetectedAt")
        or raw.get("created_at")
        or raw.get("createdAt")
    )
    locs = raw.get("locations") or raw.get("instances") or []
    repos = []
    if isinstance(locs, list):
        for loc in locs:
            if isinstance(loc, dict) and loc.get("name"):
                repos.append(str(loc["name"]))
    if not repos:
        repos = raw.get("affected_repos") or raw.get("repositories") or []
    sev = str(raw.get("severity") or "unknown").lower()
    sev_score = raw.get("severity_score")
    if sev_score is not None and isinstance(sev_score, (int, float)) and sev_score > 10:
        sev_score = round(sev_score / 10 * 10) / 10
    return {
        "group_id": raw.get("id") or raw.get("group_id") or 0,
        "title": raw.get("title") or raw.get("name") or "Unknown",
        "severity": sev,
        "severity_score": float(sev_score) if sev_score is not None else 5,
        "status": "open"
        if "open" in str(raw.get("group_status") or raw.get("status") or "").lower()
        else "closed",
        "first_detected_at": _ts_to_iso(fd),
        "issue_count": raw.get("issue_count") or raw.get("nr_of_issues") or 1,
        "affected_repos": [str(r) for r in repos] if isinstance(repos, list) else [],
        "scanner_type": raw.get("type") or raw.get("scanner_type") or "unknown",
        "cve_id": (raw.get("related_cve_ids") or [None])[0]
        if isinstance(raw.get("related_cve_ids"), list)
        else raw.get("cve_id"),
        "has_task": str(raw.get("group_status") or "").startswith("task_"),
    }


def _normalize_repo(raw: dict) -> dict:
    """Normalize repo/container/VM to VATReportRepo shape."""
    name = (
        raw.get("name")
        or raw.get("repo_name")
        or raw.get("external_repo_id")
        or "Unknown"
    )
    return {
        "id": raw.get("id") or 0,
        "name": str(name),
        "provider": str(raw.get("provider") or raw.get("source") or "aikido"),
        "issue_count": raw.get("issue_count")
        or raw.get("open_issues_count")
        or raw.get("nr_of_issues")
        or 0,
        "critical_count": raw.get("critical_count") or raw.get("nr_critical") or 0,
        "high_count": raw.get("high_count") or raw.get("nr_high") or 0,
        "medium_count": raw.get("medium_count") or raw.get("nr_medium") or 0,
        "low_count": raw.get("low_count") or raw.get("nr_low") or 0,
    }


def _progress(
    on_progress: Optional[Callable[[int, int, str], None]],
    step: int,
    total: int,
    label: str,
) -> None:
    if on_progress:
        on_progress(step, total, label)


async def sync_aikido_dashboard(
    creds: dict,
    db: AsyncSession,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    raw_issues_override: Optional[list] = None,
    repo_map: Optional[dict] = None,
    repo_id_to_name: Optional[dict] = None,
    repos_override: Optional[list] = None,
    containers_override: Optional[list] = None,
    source_id: str | None = None,
) -> dict:
    """
    Fetch all Aikido data and store in VAT settings.
    Returns the synced data (normalized for report).
    on_progress(step, total, label) called at each fetch step.
    raw_issues_override: when provided (e.g. from full sync bootstrap), use this instead of
        fetching — ensures VAT DB and Excel export use identical data for infallible validation.
    repo_map: optional {code_repo_id: branch} to enrich branch in Excel for branch-level validation.
    repo_id_to_name: optional {code_repo_id: name} when repo_map provided; avoids extra repos fetch.
    repos_override, containers_override: when provided (e.g. from full sync), use instead of fetching.
    """
    total_steps = 12
    step_num = 0

    _progress(on_progress, step_num := step_num + 1, total_steps, "Issues")
    if raw_issues_override is not None:
        raw_issues = raw_issues_override
    else:
        raw_issues = await fetch_aikido_issues(credentials=creds)

    # Build repo_map and repo_id_to_name when not provided (e.g. standalone sync-dashboard)
    _repo_id_to_name: dict = repo_id_to_name or {}
    if repo_map is None:
        try:
            repos = await fetch_aikido_code_repositories(credentials=creds)
            repo_map = {}
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
                        _repo_id_to_name[rid] = str(r["name"]).strip()
                        _repo_id_to_name[str(rid)] = str(r["name"]).strip()
        except Exception as e:
            logger.debug("Could not fetch repos for branch/name enrichment: %s", e)
            repo_map = {}
    elif not _repo_id_to_name and repos_override:
        for r in repos_override or []:
            if isinstance(r, dict) and r.get("id") is not None and r.get("name"):
                rid = r["id"]
                _repo_id_to_name[rid] = str(r["name"]).strip()
                _repo_id_to_name[str(rid)] = str(r["name"]).strip()

    _progress(on_progress, step_num := step_num + 1, total_steps, "Issue groups")
    # Disabled: VAT uses its own grouping logic; Aikido groups not needed
    # issue_groups = await fetch_aikido_open_issue_groups(credentials=creds)
    issue_groups: list = []

    _progress(on_progress, step_num := step_num + 1, total_steps, "Repositories")
    if repos_override is not None:
        repos = repos_override
    else:
        repos = await fetch_aikido_code_repositories(credentials=creds)

    _progress(on_progress, step_num := step_num + 1, total_steps, "Containers")
    if containers_override is not None:
        containers = containers_override
    else:
        containers = await fetch_aikido_containers(credentials=creds)
    _progress(on_progress, step_num := step_num + 1, total_steps, "Virtual machines")
    vms = await fetch_aikido_virtual_machines(credentials=creds)
    _progress(on_progress, step_num := step_num + 1, total_steps, "Workspace")
    workspace = await fetch_aikido_workspace(credentials=creds)
    _progress(on_progress, step_num := step_num + 1, total_steps, "Issue counts")
    issue_counts = await fetch_aikido_issue_counts(credentials=creds)
    _progress(on_progress, step_num := step_num + 1, total_steps, "Activity log")
    # Activity tracked only within VAT (Finding.audit); no Aikido activity merge to avoid drift
    activity_log: list = []
    _progress(on_progress, step_num := step_num + 1, total_steps, "CI scans")
    # ci_scans = await fetch_aikido_ci_scans(credentials=creds, limit=100)
    ci_scans: list = []
    _progress(on_progress, step_num := step_num + 1, total_steps, "Task projects")
    task_projects = await fetch_aikido_task_projects(credentials=creds)

    # Normalize issues (with repo_map and repo_id_to_name for Excel to match VAT)
    issues = [
        _normalize_issue(r, repo_map, _repo_id_to_name)
        for r in raw_issues
        if isinstance(r, dict)
    ]
    groups = [_normalize_issue_group(g) for g in issue_groups if isinstance(g, dict)]
    repos_norm = [_normalize_repo(r) for r in repos if isinstance(r, dict)]
    containers_norm = [_normalize_repo(c) for c in containers if isinstance(c, dict)]
    vms_norm = [_normalize_repo(v) for v in vms if isinstance(v, dict)]

    is_open = lambda i: (i.get("status") or "").lower() not in (
        "closed",
        "resolved",
        "ignored",
        "auto_ignored",
    )

    _progress(on_progress, step_num := step_num + 1, total_steps, "Tasks")
    # tasks_by_group = await fetch_aikido_tasks_for_groups(top_group_ids, credentials=creds, max_groups=15)
    tasks_by_group: dict = {}

    _progress(on_progress, step_num := step_num + 1, total_steps, "CVE details")
    # CVE details (EPSS/KEV) disabled — not used in reports
    # cve_ids = list({i.get("cve_id") for i in issues if is_open(i) and i.get("cve_id") and str(i.get("cve_id")) != "N/A"})[:20]
    # for cid in cve_ids:
    #     d = await fetch_aikido_cve_details(str(cid), credentials=creds)
    #     ...
    cve_details: dict[str, dict] = {}

    data = {
        "issues": issues,
        "issueGroups": groups,
        "repos": repos_norm,
        "containers": containers_norm,
        "vms": vms_norm,
        "workspace": workspace or {"id": "vat", "name": "VAT", "plan": "default"},
        "issueCounts": issue_counts,
        "activityLog": activity_log,
        "ciScans": ci_scans,
        "taskProjects": task_projects,
        "reachabilityByIssueId": {},
        "tasksByGroupId": {str(k): v for k, v in tasks_by_group.items()},
        "cveDetailsByCveId": cve_details,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }

    # Export to Excel for validation when configured
    export_dir = get_settings().aikido_export_excel_dir
    if export_dir:
        logger.info("Exporting Aikido sync to Excel (dir=%s)", export_dir)
        path = export_aikido_sync_to_excel(
            data, raw_issues=raw_issues, output_dir=export_dir
        )
        if path:
            logger.info("Aikido sync exported to %s for validation", path)
        else:
            logger.warning(
                "Aikido Excel export returned None (check pandas/openpyxl install or logs for errors)"
            )
    else:
        logger.debug("VAT_AIKIDO_EXPORT_EXCEL_DIR not set; skipping Excel export")

    # When useAikidoTracking: fetch Aikido's linked tasks and update findings' tracker links
    try:
        sync_result = await sync_aikido_tracker_links(
            db, creds, raw_issues, max_groups=20, source_id=source_id
        )
        if sync_result.get("updated", 0) > 0:
            logger.info(
                "Aikido tracker links: updated %d findings", sync_result["updated"]
            )
    except Exception as e:
        logger.warning("Aikido tracker links sync failed: %s", e)

    # Store (per-source when source_id given)
    key = _dashboard_key(source_id)
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row:
        row.value = data
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=key, value=data, updated_at=_utc_now_naive()))
    await db.commit()
    logger.info(
        "Aikido sync complete: %d issues, %d groups, %d containers, %d vms",
        len(issues),
        len(groups),
        len(containers_norm),
        len(vms_norm),
    )
    return data


async def get_aikido_dashboard_cached(
    db: AsyncSession, source_id: str | None = None
) -> Optional[dict]:
    """Return cached Aikido data synced to VAT if present. Per-source when source_id given."""
    key = _dashboard_key(source_id)
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return row.value
    return None
