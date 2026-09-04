"""Aikido source adapter — maps webhook payload to VAT canonical format.
PRD §8.4.1: issue.created, issue.updated, issue.closed events.
Bootstrap: GET /issues/export to seed existing findings.
Secrets and IaC findings map to findingType=Secret and IaC.

Auth: OAuth client credentials (client_id + client_secret + region) only.
Region: eu, us, me.

API Reference: https://apidocs.aikido.dev
- Export all issues: GET /api/public/v1/issues/export
- Container SBOM / licenses: GET /api/public/v1/containers/{id}/licenses/export
- Bulk container SBOM: POST /api/public/v1/containers/sbom/generate
- Ignore issue: PUT /api/public/v1/issues/{id}/ignore
- Unignore issue: PUT /api/public/v1/issues/{id}/unignore
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional, TextIO

import httpx

logger = logging.getLogger(__name__)

from app.adapters.registry import SourceAdapterCapabilities, register_source_adapter
from app.core.config import get_settings
from app.parsers.image_digest import effective_image_digest
from app.services.dedup import component_base as extract_component_base
from app.schemas.integration_ui import IntegrationFieldSchema, IntegrationSettingsSchema
from app.schemas.vat import (
    VatFindingSchema,
    VatFindingType,
    VatSourceIgnoreRequest,
    VatSourceUnignoreRequest,
)

REGION_BASE_URLS: dict[str, str] = {
    "eu": "https://app.aikido.dev",
    "us": "https://app.us.aikido.dev",
    "me": "https://app.me.aikido.dev",
}

_token_cache: dict[str, tuple[str, float]] = {}  # key -> (token, expires_at)

# Rate limiting (matches vulnerability-dashboard: ~15/min, 2.5s gap)
_rate_limit_last: list[float] = [0.0]
_rate_limit_lock = asyncio.Lock()

# Module-level shared httpx client. Per-call AsyncClient() instances pay
# TCP+TLS handshake on every request (~50-200ms each); a pooled client
# reuses connections. Transport-level retries=3 absorbs single connect
# blips (DNS hiccups, TCP RST) without bubbling up to callers.
_aikido_http_client: Optional[httpx.AsyncClient] = None
_aikido_http_lock = asyncio.Lock()


def _aikido_client() -> httpx.AsyncClient:
    """Lazy module-level httpx client for Aikido. Per-request `timeout=`
    overrides the default. Each uvicorn worker / Celery prefork worker
    gets its own client bound to that worker's event loop.
    """
    global _aikido_http_client
    if _aikido_http_client is None or _aikido_http_client.is_closed:
        # Default timeout = 60s; callers pass timeout= for longer/shorter
        # bounds. retries=3 at transport layer handles ConnectError /
        # ReadTimeout reconnects on a single retry, without callers needing
        # to track attempt counts.
        _aikido_http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            transport=httpx.AsyncHTTPTransport(retries=3),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _aikido_http_client


async def aclose_aikido_client() -> None:
    """Best-effort shutdown helper. Called from app lifespan."""
    global _aikido_http_client
    if _aikido_http_client is not None and not _aikido_http_client.is_closed:
        await _aikido_http_client.aclose()
    _aikido_http_client = None


async def _acquire_rate_limit_slot() -> None:
    """Wait until we can make another Aikido API request (min gap between requests)."""
    s = get_settings()
    gap_s = s.aikido_request_gap_ms / 1000.0
    async with _rate_limit_lock:
        now = time.monotonic()
        elapsed = now - _rate_limit_last[0]
        if elapsed < gap_s:
            await asyncio.sleep(gap_s - elapsed)
        _rate_limit_last[0] = time.monotonic()


# Aikido issue types → VAT finding types (PRD §5.1.3)
TYPE_MAP = {
    "vulnerability": VatFindingType.SCA,
    "cve": VatFindingType.SCA,
    "dependency": VatFindingType.SCA,
    "secret": VatFindingType.SECRET,
    "leaked_secret": VatFindingType.SECRET,
    "credential": VatFindingType.SECRET,
    "iac": VatFindingType.IAC,
    "infrastructure": VatFindingType.IAC,
    "misconfiguration": VatFindingType.IAC,
    "sast": VatFindingType.SAST,
    "code": VatFindingType.SAST,
    "license": VatFindingType.LICENSE,
}


def _get_nested(obj: dict, *keys: str, default=None):
    """Get value from nested dict keys."""
    for k in keys:
        if isinstance(obj, dict) and k in obj:
            obj = obj[k]
        else:
            return default
    return obj


def _extract_branch(
    issue: dict, repo_map: Optional[dict[int | str, str]] = None
) -> str | None:
    """
    Extract git branch for code repos. Per Aikido API (apidocs.aikido.dev):
    - Top-level: branch, git_branch, code_repo_branch, scanned_branch, ref
    - locations[].branch, locations[].scanned_branch
    - code_repository.branch (nested object)
    - repo_map: optional {code_repo_id: branch} from GET /repositories/code (Aikido clones per branch)
    """
    # Aikido multi-branch: each branch is a separate repo; code_repo_id maps to branch via repos API
    if repo_map:
        repo_id = issue.get("code_repo_id") or issue.get("codeRepoId")
        if repo_id is not None:
            branch = repo_map.get(repo_id) or repo_map.get(str(repo_id))
            if not branch:
                try:
                    branch = repo_map.get(int(repo_id))
                except (TypeError, ValueError):
                    pass
            if branch:
                return str(branch).strip()

    def _s(v) -> str | None:
        if v is None or not isinstance(v, str):
            return None
        t = v.strip()
        return t if t else None

    # Top-level keys (Aikido export / webhook)
    for key in (
        "branch",
        "git_branch",
        "target_branch",
        "ref",
        "code_repo_branch",
        "codeRepoBranch",
        "scanned_branch",
        "scannedBranch",
        "default_branch",
        "defaultBranch",
        "base_branch",
        "baseBranch",
        "repository_branch",
        "repositoryBranch",
    ):
        v = issue.get(key)
        if v and (r := _s(str(v))):
            return r
    # Nested: code_repository.branch
    code_repo = issue.get("code_repository") or issue.get("codeRepository")
    if isinstance(code_repo, dict):
        for k in ("branch", "scanned_branch", "scannedBranch", "default_branch", "ref"):
            v = code_repo.get(k)
            if v and (r := _s(str(v))):
                return r
    # locations array: [{ type: "code_repository", branch, scanned_branch, ... }]
    locations = (
        issue.get("locations") or issue.get("instances") or issue.get("locations_list")
    )
    if isinstance(locations, list) and locations:
        for loc in locations:
            if isinstance(loc, dict):
                for k in (
                    "branch",
                    "git_branch",
                    "target_branch",
                    "ref",
                    "scanned_branch",
                    "scannedBranch",
                ):
                    v = loc.get(k)
                    if v and (r := _s(str(v))):
                        return r
    return None


def _extract_image_digest_from_issue(issue: dict, image_ref: str | None) -> str | None:
    """Best-effort sha256 digest for container correlation (merge suggestions, digest facts)."""
    if not isinstance(issue, dict):
        return effective_image_digest(None, image_ref)

    def _try_string(s: str) -> str | None:
        d = effective_image_digest(s.strip(), None)
        return d if d else None

    for key in (
        "image_digest",
        "imageDigest",
        "container_digest",
        "containerDigest",
        "manifest_digest",
        "manifestDigest",
    ):
        v = issue.get(key)
        if isinstance(v, str) and v.strip():
            d = _try_string(v)
            if d:
                return d
    for nested in (issue.get("container"), issue.get("container_image")):
        if isinstance(nested, dict):
            for key in ("digest", "image_digest", "imageDigest", "manifest_digest"):
                v = nested.get(key)
                if isinstance(v, str) and v.strip():
                    d = _try_string(v)
                    if d:
                        return d
    return effective_image_digest(None, image_ref)


def _normalize_aikido_license_type(value: str | None) -> str | None:
    """Pick the highest-risk SPDX id from Aikido's ``license_type`` field.

    Aikido may emit a single SPDX id (``GPL-3.0``), a non-SPDX bucket
    (``Proprietary``), or a comma-separated list of identifiers
    (``AGPL-3,Apache-2.0,...``). For correlation we pick the highest-risk
    SPDX-recognizable token via ``license_risk_tier`` so cross-source keys
    align with the cyclonedx side, which uses the same risk-ranked picker.
    """
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if "," not in raw:
        return raw
    from app.models.sbom import _LICENSE_RISK_RANK, license_risk_tier

    candidates = [tok.strip() for tok in raw.split(",") if tok.strip()]
    if not candidates:
        return raw
    best = candidates[0]
    best_rank = _LICENSE_RISK_RANK.get(license_risk_tier(best), 99)
    for cand in candidates[1:]:
        rank = _LICENSE_RISK_RANK.get(license_risk_tier(cand), 99)
        if rank < best_rank:
            best = cand
            best_rank = rank
    return best


def _strip_tag_from_container_name(name: str | None) -> str | None:
    """Remove :tag from container image/repo name. e.g. containers/images/foo:latest -> containers/images/foo."""
    if not name or not isinstance(name, str):
        return name
    s = name.strip()
    if ":" in s:
        return s.rsplit(":", 1)[0].strip() or s
    return s


def _tag_from_image_ref(value: str | None) -> str | None:
    """Parse :tag from an image ref; None if digest-pinned, missing tag, or ambiguous (port)."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if "@sha256:" in s.lower():
        return None
    if ":" not in s:
        return None
    tag = s.rsplit(":", 1)[-1].strip()
    if not tag or tag.isdigit() or "/" in tag:
        return None
    return tag


def _extra_tags_from_value(val: Any) -> list[str]:
    """Extract tag-like strings from nested Aikido fields (lists/dicts of image refs)."""
    out: list[str] = []
    if val is None:
        return out
    if isinstance(val, str):
        tt = _tag_from_image_ref(val)
        if tt:
            out.append(tt)
        return out
    if isinstance(val, list):
        for x in val:
            out.extend(_extra_tags_from_value(x))
        return out
    if isinstance(val, dict):
        for k in (
            "tag",
            "image_tag",
            "imageTag",
            "image",
            "name",
            "reference",
            "ref",
            "docker_image",
            "dockerImage",
        ):
            if k in val:
                out.extend(_extra_tags_from_value(val[k]))
    return out


def _collect_container_tags_from_issue(issue: dict) -> list[str]:
    """
    All distinct container tags on an Aikido issue: top-level fields, nested container,
    and locations / instances (where multi-tag deployments often appear).
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        if not raw or not isinstance(raw, str):
            return
        t = raw.strip()
        if not t or t in seen:
            return
        seen.add(t)
        found.append(t)

    for key in ("container_tag", "containerTag", "tag", "image_tag", "imageTag"):
        v = issue.get(key)
        if v is not None:
            add(str(v))
    for key in ("image", "container_repo_name", "containerRepoName"):
        v = issue.get(key)
        if isinstance(v, str):
            tt = _tag_from_image_ref(v)
            if tt:
                add(tt)
    for nest_key in ("container", "container_image", "containerImage"):
        nested = issue.get(nest_key)
        if not isinstance(nested, dict):
            continue
        for key in ("tag", "image_tag", "imageTag", "name", "image"):
            v = nested.get(key)
            if not isinstance(v, str):
                continue
            if key in ("name", "image"):
                tt = _tag_from_image_ref(v)
                if tt:
                    add(tt)
            else:
                add(v)
    locations = (
        issue.get("locations")
        or issue.get("instances")
        or issue.get("locations_list")
        or []
    )
    if isinstance(locations, list):
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            for arr_key in ("tags", "image_tags", "imageTags"):
                raw_tags = loc.get(arr_key)
                if isinstance(raw_tags, list):
                    for x in raw_tags:
                        if isinstance(x, str):
                            add(x)
            for key in (
                "tag",
                "image_tag",
                "imageTag",
                "container_tag",
                "containerTag",
                "scanned_tag",
                "scannedTag",
            ):
                v = loc.get(key)
                if isinstance(v, str):
                    add(v)
            for key in ("image", "name", "container_image", "containerImage"):
                v = loc.get(key)
                if isinstance(v, str):
                    tt = _tag_from_image_ref(v)
                    if tt:
                        add(tt)
            nested = loc.get("container") or loc.get("container_image")
            if isinstance(nested, dict):
                for key in ("tag", "image_tag", "imageTag", "image", "name"):
                    v = nested.get(key)
                    if isinstance(v, str):
                        if key in ("image", "name"):
                            tt = _tag_from_image_ref(v)
                            if tt:
                                add(tt)
                        else:
                            add(v)
    for key in (
        "docker_image",
        "dockerImage",
        "full_image",
        "fullImage",
        "scan_image",
        "scanImage",
        "affected_images",
        "affectedImages",
        "image_refs",
        "imageRefs",
        "container_images",
        "containerImages",
    ):
        for t in _extra_tags_from_value(issue.get(key)):
            add(t)
    return found


def _extract_tag(issue: dict, asset_name: str | None) -> str | None:
    """Primary container tag for the finding row; prefers explicit tags over literal latest."""
    collected = _collect_container_tags_from_issue(issue)
    if collected:
        non_latest = [t for t in collected if t.lower() != "latest"]
        return non_latest[0] if non_latest else collected[0]
    if asset_name and isinstance(asset_name, str):
        tt = _tag_from_image_ref(asset_name)
        if tt:
            return tt
    return None


def aikido_container_list_item_tags(c: dict) -> list[str]:
    """
    Tags from GET /containers list item: arrays (``tags``, ``image_tags``), single fields,
    or ``:tag`` / ``@sha256`` handling on name/image.
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        if not raw or not isinstance(raw, str):
            return
        t = raw.strip()
        if not t or t in seen:
            return
        seen.add(t)
        found.append(t)

    for arr_key in ("tags", "image_tags", "imageTags"):
        raw = c.get(arr_key)
        if isinstance(raw, list):
            for x in raw:
                if isinstance(x, str):
                    add(x)
    for key in ("tag", "image_tag", "imageTag"):
        v = c.get(key)
        if isinstance(v, str):
            add(v)
    name = (
        c.get("name")
        or c.get("image")
        or c.get("repository_name")
        or c.get("repositoryName")
    )
    if isinstance(name, str):
        tt = _tag_from_image_ref(name)
        if tt:
            add(tt)
    for key in (
        "docker_image",
        "dockerImage",
        "full_image",
        "fullImage",
        "docker_tags",
        "dockerTags",
    ):
        for t in _extra_tags_from_value(c.get(key)):
            add(t)
    return found


def _parse_repo_name_with_branch(name: str) -> tuple[str, str | None]:
    """
    Aikido multi-branch creates cloned repos with branch in the name.
    Parse "kamiwaza (main)", "kamiwaza (develop)", "kamiwaza (release/0.10.0)",
    "kamiwaza - main", etc. Returns (base_name, branch) or (name, None) if no branch suffix.
    """
    import re

    if not name or not isinstance(name, str):
        return (name or "", None)
    name = name.strip()
    # Match "name (branch)" — branch can contain / e.g. release/0.10.0
    m = re.match(r"^(.+?)\s*\(\s*([^)]+)\s*\)\s*$", name)
    if m:
        base, branch = m.group(1).strip(), m.group(2).strip()
        if base and branch:
            return (base, branch)
    # Match "name - branch" at end (branch can contain /)
    m = re.match(r"^(.+?)\s+-\s+(.+)$", name)
    if m:
        base, branch = m.group(1).strip(), m.group(2).strip()
        if base and branch:
            return (base, branch)
    # Match "name/branch" or "name:branch" (Aikido may use these)
    m = re.match(r"^(.+?)[/:]([^/:]+)$", name)
    if m:
        base, branch = m.group(1).strip(), m.group(2).strip()
        if base and branch:
            return (base, branch)
    return (name, None)


def _extract_branch_from_repo(repo: dict) -> str | None:
    """
    Extract branch from Aikido repository object. API may use snake_case or camelCase.
    """
    if not isinstance(repo, dict):
        return None
    for key in (
        "branch",
        "default_branch",
        "defaultBranch",
        "git_branch",
        "gitBranch",
        "scanned_branch",
        "scannedBranch",
        "ref",
    ):
        v = repo.get(key)
        if v is not None and isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _extract_file_location(issue: dict) -> tuple[str | None, int | None]:
    """
    Extract file path and line from Aikido payload for location-based grouping.
    Returns (file_path, line) where line may be None.
    """
    # Top-level
    path = _get_nested(issue, "affected_file") or _get_nested(issue, "affectedFile")
    path = path or _get_nested(issue, "file_path") or _get_nested(issue, "filePath")
    path = path or _get_nested(issue, "path") or _get_nested(issue, "file")
    line = (
        _get_nested(issue, "line")
        or _get_nested(issue, "line_number")
        or _get_nested(issue, "lineNumber")
        or _get_nested(issue, "start_line")
        or _get_nested(issue, "startLine")
    )
    if path and isinstance(path, str) and path.strip():
        path_str = path.strip()
        line_int = int(line) if line is not None and str(line).isdigit() else None
        return (path_str, line_int)

    # locations[0] — first location often has path and line
    locations = (
        issue.get("locations") or issue.get("instances") or issue.get("locations_list")
    )
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        loc = locations[0]
        path = (
            loc.get("path")
            or loc.get("file_path")
            or loc.get("filePath")
            or loc.get("file")
            or loc.get("path")
        )
        line = (
            loc.get("line")
            or loc.get("line_number")
            or loc.get("lineNumber")
            or loc.get("start_line")
            or loc.get("startLine")
        )
        if path and isinstance(path, str) and path.strip():
            line_int = int(line) if line is not None and str(line).isdigit() else None
            return (path.strip(), line_int)

    return (None, None)


def _extract_issue_url(issue: dict) -> str | None:
    """Extract dashboard URL for this issue from Aikido payload, if provided."""

    def _valid(v):
        if not v or not isinstance(v, str):
            return None
        v = v.strip()
        if v.startswith("http://") or v.startswith("https://"):
            return v
        return None

    for key in ("issue_url", "web_url", "url", "link", "dashboard_url", "permalink"):
        if u := _valid(issue.get(key)):
            return u
    return None


def _to_resource_id(v) -> str | None:
    """Convert API value to string ID."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return str(int(float(v)))
    if isinstance(v, str) and v.strip().replace("-", "").isdigit():
        return str(int(float(v.strip())))
    return None


def _extract_resource_path_and_id(
    issue: dict,
    container_name_to_id: Optional[dict[str, str]] = None,
) -> tuple[str, str] | None:
    """
    Extract (path_segment, resource_id) for Aikido dashboard URL.
    API paths: /repositories/code, /containers/{id}, /clouds, /domains, /virtual-machines.
    Dashboard mirrors these: /repositories/{id}, /containers/{id}, /clouds/{id}, etc.
    Uses attack_surface and available IDs per export schema.
    container_name_to_id: optional map from container name/path to numeric ID (from GET /containers).
    """
    attack_surface = str(
        issue.get("attack_surface") or issue.get("attackSurface") or ""
    ).lower()

    def _container_rid() -> str | None:
        rid = _to_resource_id(
            issue.get("container_repo_id") or issue.get("containerRepoId")
        )
        if rid:
            return rid
        rid = _to_resource_id(issue.get("container_id") or issue.get("containerId"))
        if rid:
            return rid
        if container_name_to_id:
            name = (
                issue.get("container_repo_name")
                or issue.get("containerRepoName")
                or _extract_asset_name(issue)
            )
            if name:
                name_stripped = _strip_tag_from_container_name(str(name)) or str(name)
                return container_name_to_id.get(
                    name_stripped
                ) or container_name_to_id.get(str(name))
        return None

    # Prefer resource matching attack_surface
    if attack_surface == "docker_container":
        if rid := _container_rid():
            return ("containers", rid)
    elif attack_surface == "cloud":
        if rid := _to_resource_id(issue.get("cloud_id") or issue.get("cloudId")):
            return ("clouds", rid)

    # Code/backend/frontend: use code_repo_id → /repositories/{id}
    if rid := _to_resource_id(issue.get("code_repo_id") or issue.get("codeRepoId")):
        return ("repositories", rid)
    if rid := _container_rid():
        return ("containers", rid)
    if rid := _to_resource_id(issue.get("cloud_id") or issue.get("cloudId")):
        return ("clouds", rid)
    if rid := _to_resource_id(issue.get("domain_id") or issue.get("domainId")):
        return ("domains", rid)
    if rid := _to_resource_id(
        issue.get("virtual_machine_id") or issue.get("virtualMachineId")
    ):
        return ("virtual-machines", rid)

    # Nested
    for repo_key in ("code_repository", "codeRepository"):
        repo = issue.get(repo_key)
        if isinstance(repo, dict) and (rid := _to_resource_id(repo.get("id"))):
            return ("repositories", rid)
    for repo_key in ("container_repository", "containerRepository"):
        repo = issue.get(repo_key)
        if isinstance(repo, dict):
            rid = _to_resource_id(
                repo.get("id")
                or repo.get("container_repo_id")
                or repo.get("containerRepoId")
                or repo.get("container_id")
                or repo.get("containerId")
            )
            if rid:
                return ("containers", rid)

    # locations / instances
    for arr_key in ("locations", "instances", "locations_list"):
        arr = issue.get(arr_key)
        if isinstance(arr, list) and arr:
            for loc in arr:
                if isinstance(loc, dict):
                    if rid := _to_resource_id(
                        loc.get("code_repo_id")
                        or loc.get("codeRepoId")
                        or loc.get("repository_id")
                    ):
                        return ("repositories", rid)
                    if rid := _to_resource_id(
                        loc.get("container_repo_id")
                        or loc.get("containerRepoId")
                        or loc.get("container_id")
                        or loc.get("containerId")
                    ):
                        return ("containers", rid)

    return None


def _extract_source_file_url(issue: dict) -> str | None:
    """
    Extract direct URL to file at line from Aikido payload.
    Aikido provides clickable links; try common field names.
    """

    def _valid_url(v) -> str | None:
        if not v or not isinstance(v, str):
            return None
        v = v.strip()
        if v.startswith("http://") or v.startswith("https://"):
            return v
        return None

    # Top-level
    for key in (
        "url",
        "link",
        "file_url",
        "affected_file_url",
        "source_url",
        "location_url",
        "issue_url",
        "web_url",
        "html_url",
        "code_url",
        "blob_url",
    ):
        v = issue.get(key)
        if u := _valid_url(v):
            return u

    # Nested: code_repository
    code_repo = issue.get("code_repository") or issue.get("codeRepository")
    if isinstance(code_repo, dict):
        for key in ("url", "html_url", "web_url", "repository_url", "blob_url"):
            v = code_repo.get(key)
            if u := _valid_url(v):
                return u

    # locations[0] — first location often has file URL
    locations = (
        issue.get("locations") or issue.get("instances") or issue.get("locations_list")
    )
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        loc = locations[0]
        for key in ("url", "link", "file_url", "html_url", "web_url", "blob_url"):
            v = loc.get(key)
            if u := _valid_url(v):
                return u

    return None


def _extract_asset_name(issue: dict) -> str | None:
    """
    Extract the asset (repository/container) name for grouping findings.
    Aikido uses code_repo_name (code), container_repo_name (containers), locations, etc.
    For multi-branch: code_repo_name may be "repo (branch)" — we normalize to base name.
    """

    def _s(v) -> str | None:
        if v is None or not isinstance(v, str):
            return None
        t = v.strip()
        return t if t else None

    # Aikido primary fields — prefer container_repo_name for container issues
    for key in (
        "container_repo_name",
        "containerRepoName",
        "code_repo_name",
        "codeRepoName",
    ):
        v = issue.get(key)
        if v and (r := _s(str(v))):
            return r
    # Nested code_repository / codeRepository (Aikido may put repo name here)
    code_repo = issue.get("code_repository") or issue.get("codeRepository")
    if isinstance(code_repo, dict) and code_repo.get("name"):
        if r := _s(str(code_repo["name"])):
            return r
    # locations array: [{ type: "code_repository"|"container_repository", name: "..." }]
    locations = (
        issue.get("locations") or issue.get("instances") or issue.get("locations_list")
    )
    if isinstance(locations, list) and locations:
        for loc in locations:
            if isinstance(loc, dict) and loc.get("name"):
                loc_type = str(loc.get("type", "")).lower()
                name = str(loc["name"]).strip()
                if name and (
                    "container" in loc_type or "code" in loc_type or "repo" in loc_type
                ):
                    return name
                if name:
                    return name
    # Fallbacks (support snake_case and camelCase)
    for key in (
        "repository",
        "repo",
        "repo_name",
        "repoName",
        "image",
        "target",
        "registry_name",
        "registryName",
    ):
        val = issue.get(key)
        if val and (r := _s(str(val))):
            return r
    return None


def _infer_ecosystem(issue: dict, comp: str, asset_name: str | None) -> str | None:
    """
    Infer package ecosystem for SCA/License findings when Aikido does not provide it.
    Uses programming_language if present, else heuristics from repo + package name.
    """
    # Aikido may provide programming_language or package_manager
    lang = (
        _get_nested(issue, "programming_language")
        or _get_nested(issue, "programmingLanguage")
        or _get_nested(issue, "package_manager")
        or _get_nested(issue, "packageManager")
    )
    if lang and isinstance(lang, str):
        l = lang.lower().strip()
        if l in ("python", "pip", "pipenv", "poetry"):
            return "pypi"
        if l in ("javascript", "node", "npm", "yarn", "pnpm"):
            return "npm"
        if l in ("java", "maven", "gradle"):
            return "maven"
        if l in ("go", "golang"):
            return "go"
        if l in ("rust", "cargo"):
            return "cargo"
        if l in ("ruby", "bundler"):
            return "rubygems"
        if l in ("php", "composer"):
            return "packagist"
        if l in ("debian", "ubuntu", "alpine"):
            return "debian"

    pkg = (comp or "").lower()
    repo = (asset_name or "").lower()

    # Container images often use debian/ubuntu base
    if "images" in repo or "container" in repo:
        return "debian"

    # Infer from package name patterns
    if pkg:
        if "." in pkg and not pkg.startswith(("org.", "com.")):
            return "pypi"
        if pkg.startswith(("org.", "com.")) or ("-" in pkg and "java" in repo):
            return "maven"
        if pkg in ("next.js", "nextjs", "react", "lodash") or pkg.endswith(".js"):
            return "npm"

    return None


@register_source_adapter("aikido")
class AikidoAdapter:
    """Aikido webhook adapter. Events: issue.created, issue.updated, issue.closed."""

    def __init__(self, credentials: Optional[dict[str, Any]] = None):
        self._credentials = credentials
        self._container_name_to_id_cache: Optional[dict[str, str]] = None

    @classmethod
    def get_settings_schema(cls) -> IntegrationSettingsSchema:
        """Schema for settings canvas. OAuth + webhook secret."""
        return IntegrationSettingsSchema(
            adapter_key="aikido",
            display_name="Aikido",
            description="Vulnerability scanning, SBOM, and secrets detection. Webhook + OAuth.",
            fields=[
                IntegrationFieldSchema(
                    key="client_id",
                    label="Client ID",
                    type="text",
                    required=True,
                    help_text="OAuth client ID from Aikido dashboard",
                ),
                IntegrationFieldSchema(
                    key="client_secret",
                    label="Client Secret",
                    type="password",
                    required=True,
                    help_text="OAuth client secret",
                ),
                IntegrationFieldSchema(
                    key="region",
                    label="Region",
                    type="select",
                    required=False,
                    default="eu",
                    options=[
                        {"value": "eu", "label": "EU (app.aikido.dev)"},
                        {"value": "us", "label": "US (app.us.aikido.dev)"},
                        {"value": "me", "label": "Middle East (app.me.aikido.dev)"},
                    ],
                    help_text="Aikido region for API and webhooks",
                ),
                IntegrationFieldSchema(
                    key="webhook_secret",
                    label="Webhook Secret",
                    type="password",
                    required=False,
                    help_text="Optional: verify webhook signatures (X-Aikido-Webhook-Signature)",
                ),
            ],
            supports_test_connection=True,
            logo_url="https://app.aikido.dev/favicon.ico",
            brand_color="#10B981",
            icon="shield",
        )

    def get_capabilities(self) -> SourceAdapterCapabilities:
        return SourceAdapterCapabilities(
            supports_ignore=True,
            supports_unignore=True,
            supports_inbound_sync=True,  # Webhooks push updates to VAT
        )

    async def to_vat_finding(
        self,
        payload: dict,
        repo_map: Optional[dict[int | str, str]] = None,
        repo_id_to_name: Optional[dict[int | str, str]] = None,
        container_name_to_id: Optional[dict[str, str]] = None,
    ) -> VatFindingSchema:
        """Transform Aikido payload to VAT canonical format. Supports top-level and payload.issue structure.
        repo_map: optional {code_repo_id: branch} from fetch_aikido_code_repositories for multi-branch.
        repo_id_to_name: optional {code_repo_id: name} from fetch_aikido_code_repositories; used when
            code_repo_name is missing so we group by repo (e.g. kamiwaza) instead of component (package).
        container_name_to_id: optional {container_name_or_path: id} from GET /containers; used when
            container_repo_id is missing to resolve Aikido dashboard links for container findings.
        """
        # Aikido may wrap in { event, payload: { issue: {...} } } or { issue: {...} }
        issue = (
            payload.get("issue") or payload.get("payload", {}).get("issue") or payload
        )

        # Resolve container name -> id map on demand (webhook path may lack container_repo_id).
        # We only do this when credentials are available and caller did not provide a map.
        if container_name_to_id is None and self._credentials:
            is_container_hint = bool(
                issue.get("container_repo_name")
                or issue.get("containerRepoName")
                or str(
                    issue.get("attack_surface") or issue.get("attackSurface") or ""
                ).lower()
                == "docker_container"
            )
            if is_container_hint:
                if self._container_name_to_id_cache is None:
                    try:
                        containers = await fetch_aikido_containers(
                            credentials=self._credentials
                        )
                        container_map: dict[str, str] = {}
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
                            if not name:
                                continue
                            name_str = str(name).strip()
                            if not name_str:
                                continue
                            name_no_tag = (
                                _strip_tag_from_container_name(name_str) or name_str
                            )
                            container_map[name_str] = sid
                            container_map[name_no_tag] = sid
                        self._container_name_to_id_cache = container_map
                    except Exception:
                        self._container_name_to_id_cache = {}
                container_name_to_id = self._container_name_to_id_cache

        raw_type = (
            _get_nested(issue, "type")
            or _get_nested(issue, "category")
            or _get_nested(issue, "finding_type")
            or _get_nested(issue, "kind")
            or ""
        )
        if isinstance(raw_type, dict):
            raw_type = raw_type.get("name") or raw_type.get("id") or ""
        raw_type = str(raw_type).lower()

        finding_type = VatFindingType.SCA
        for k, v in TYPE_MAP.items():
            if k in raw_type:
                finding_type = v
                break

        cve_id = (
            _get_nested(issue, "cve_id")
            or _get_nested(issue, "cveId")
            or _get_nested(issue, "id")
            or _get_nested(issue, "identifier")
            or "unknown"
        )
        if isinstance(cve_id, dict):
            cve_id = cve_id.get("id") or cve_id.get("name") or "unknown"
        cve_id = str(cve_id)

        comp = (
            _get_nested(issue, "component")
            or _get_nested(issue, "package")
            or _get_nested(issue, "package_name")
            or _get_nested(issue, "affected_package")
            or _get_nested(issue, "affected_component")
            or ""
        )
        if isinstance(comp, dict):
            comp = comp.get("name") or comp.get("version") or ""
        comp = str(comp)
        version = _get_nested(issue, "version") or _get_nested(
            issue, "installed_version"
        )
        if comp and version:
            comp = f"{comp} {version}"

        sev = (
            _get_nested(issue, "severity")
            or _get_nested(issue, "criticality")
            or _get_nested(issue, "risk")
            or "medium"
        )
        if isinstance(sev, dict):
            sev = sev.get("name") or sev.get("level") or "medium"
        sev = str(sev).lower()

        # Asset for grouping: repo/container name so findings from same asset group together
        raw_asset = _extract_asset_name(issue)
        is_container = bool(
            issue.get("container_repo_name") or issue.get("containerRepoName")
        )
        # Container paths (containers/images/etcd, kamiwaza/images/vllm): use full path as-is.
        # Aikido never has bare containers/images; always containers/images/<name>.
        # Strip :tag from asset name — tag is stored separately for the dropdown.
        if (
            raw_asset
            and is_container
            and "/images/" in raw_asset
            and raw_asset.count("/") >= 2
        ):
            asset_name = _strip_tag_from_container_name(raw_asset)
            branch_from_name = None
        elif raw_asset:
            # Aikido multi-branch uses "repo (branch)" in code_repo_name — parse to get base + branch
            base_name, branch_from_name = _parse_repo_name_with_branch(raw_asset)
            asset_name = base_name
        else:
            asset_name = raw_asset
            branch_from_name = None
        branch = _extract_branch(issue, repo_map) or branch_from_name
        tag = _extract_tag(issue, asset_name)
        # Defaults when Aikido doesn't provide: main for repos, latest for containers
        is_container = bool(
            issue.get("container_repo_name") or issue.get("containerRepoName")
        )
        if not is_container:
            locs = issue.get("locations") or issue.get("instances") or []
            if isinstance(locs, list) and locs and isinstance(locs[0], dict):
                is_container = "container" in str(locs[0].get("type", "")).lower()
        if not branch and not is_container:
            branch = "main"
        if not asset_name:
            fallback = (
                _get_nested(issue, "image")
                or _get_nested(issue, "target")
                or _get_nested(issue, "repository")
                or _get_nested(issue, "code_repo_name")
                or _get_nested(issue, "codeRepoName")
            )
            if fallback:
                fallback_str = str(fallback).strip()
                # Parse "repo (branch)" so image=base_name matches VAT filter (image=kamiwaza, branch=develop)
                parsed_base, parsed_branch = _parse_repo_name_with_branch(fallback_str)
                asset_name = parsed_base if parsed_base else fallback_str
                if parsed_branch and not branch:
                    branch = parsed_branch
            else:
                asset_name = None
        # For code repos: use repo name from repo_id_to_name when code_repo_name is missing.
        # Do NOT use component (package) for code repos — kamiwaza is a repo, not a package.
        repo_id = issue.get("code_repo_id") or issue.get("codeRepoId")
        if not asset_name and repo_id is not None and repo_id_to_name:
            repo_name = repo_id_to_name.get(repo_id) or repo_id_to_name.get(
                str(repo_id)
            )
            if repo_name:
                parsed_base, parsed_branch = _parse_repo_name_with_branch(
                    str(repo_name)
                )
                asset_name = parsed_base if parsed_base else str(repo_name).strip()
                if parsed_branch and not branch:
                    branch = parsed_branch
        # Fallback: use component (package) only when NOT a code repo finding (no code_repo_id)
        if not asset_name and comp and repo_id is None:
            asset_name = comp

        # Title: Aikido uses rule (SAST), affected_package+type (SCA), or fallback to cve_id.
        # For secrets and other non-CVE types, Aikido may use rule_name, secret_type, affected_file.
        title = (
            _get_nested(issue, "title")
            or _get_nested(issue, "name")
            or _get_nested(issue, "rule")
            or _get_nested(issue, "rule_name")
            or _get_nested(issue, "ruleName")
            or _get_nested(issue, "secret_type")
            or _get_nested(issue, "secretType")
            or _get_nested(issue, "detector_type")
            or _get_nested(issue, "detectorType")
        )
        if isinstance(title, dict):
            title = title.get("name") or title.get("id") or title.get("title") or ""
        title = str(title).strip() if title else ""

        if not title and comp and raw_type:
            title = f"{comp} ({raw_type})"

        # When cve_id is numeric (Aikido issue ID), avoid using it as title — build descriptive fallback
        cve_id_numeric = cve_id.isdigit() if cve_id else False
        if not title:
            if cve_id_numeric:
                # Secrets: "Leaked secret in {asset}" or "Secret ({type})"
                if finding_type == VatFindingType.SECRET:
                    af = _get_nested(issue, "affected_file") or _get_nested(
                        issue, "affectedFile"
                    )
                    if af:
                        title = f"Leaked secret in {af}"
                    elif asset_name:
                        title = f"Leaked secret in {asset_name}"
                    else:
                        title = f"Secret ({raw_type or 'leaked_secret'})"
                # IaC/SAST: use type + location
                elif finding_type in (VatFindingType.IAC, VatFindingType.SAST):
                    af = _get_nested(issue, "affected_file") or _get_nested(
                        issue, "affectedFile"
                    )
                    if af and raw_type:
                        title = f"{raw_type.replace('_', ' ').title()} in {af}"
                    elif asset_name and raw_type:
                        title = f"{raw_type.replace('_', ' ').title()} in {asset_name}"
                    else:
                        title = f"Finding ({raw_type or 'unknown'})"
                else:
                    title = f"Finding ({raw_type or 'unknown'})" if raw_type else cve_id
            else:
                title = cve_id

        # Extract file location early so we can include line in description
        source_file_url = _extract_source_file_url(issue)
        file_path, line = _extract_file_location(issue)

        # Description: Aikido uses affected_file, cwe_classes, or build from available fields
        desc = _get_nested(issue, "description") or ""
        if not desc:
            parts = []
            if file_path:
                parts.append(
                    f"File: {file_path}"
                    + (f" (line {line})" if line is not None else "")
                )
            elif af := _get_nested(issue, "affected_file") or _get_nested(
                issue, "affectedFile"
            ):
                parts.append(
                    f"File: {af}" + (f" (line {line})" if line is not None else "")
                )
            if cwe := _get_nested(issue, "cwe_classes"):
                if isinstance(cwe, list) and cwe:
                    parts.append(f"CWE: {', '.join(str(x) for x in cwe[:5])}")
                elif isinstance(cwe, str) and cwe.strip():
                    parts.append(f"CWE: {cwe}")
            if raw_type:
                parts.append(f"Type: {raw_type}")
            if parts:
                desc = " | ".join(parts)

        cvss_raw = (
            _get_nested(issue, "cvss")
            or _get_nested(issue, "score")
            or _get_nested(issue, "severity_score")
            or _get_nested(issue, "original_cvss_severity_score")
        )

        source_issue_id = None
        raw_id = _get_nested(issue, "id") or _get_nested(issue, "issue_id")
        if raw_id is not None:
            source_issue_id = str(raw_id)

        source_issue_group_id = None
        raw_group_id = _get_nested(issue, "group_id") or _get_nested(
            issue, "issue_group_id"
        )
        if raw_group_id is not None:
            source_issue_group_id = str(raw_group_id)

        # Prefer Aikido-provided URL if present; else build /{path}/{resource_id}?sidebarIssue={group_id}
        # Per API: repositories (code), containers, clouds, domains, virtual-machines
        source_issue_url = _extract_issue_url(issue)
        if not source_issue_url:
            sidebar_id = source_issue_group_id or source_issue_id
            if sidebar_id:
                region = (self._credentials or {}).get("region") or "eu"
                base = _get_base_url(region)
                resource = _extract_resource_path_and_id(
                    issue, container_name_to_id=container_name_to_id
                )
                if resource:
                    path_seg, res_id = resource
                    source_issue_url = (
                        f"{base}/{path_seg}/{res_id}?sidebarIssue={sidebar_id}"
                    )
                else:
                    source_issue_url = f"{base}/queue?sidebarIssue={sidebar_id}"

        # first_detected_at from Aikido GET /issues/export — for report trend alignment with vulnerability-dashboard
        # API ref: https://apidocs.aikido.dev/reference/exportissues
        # Live schema: first_detected_at is Unix timestamp (seconds); closed_at same. See docs/aikido-issues-export-schema.json
        first_detected_raw = (
            _get_nested(issue, "first_detected_at")
            or _get_nested(issue, "firstDetectedAt")
            or _get_nested(issue, "last_detected_at")
            or _get_nested(issue, "lastDetectedAt")
            or _get_nested(issue, "detected_at")
            or _get_nested(issue, "detectedAt")
            or _get_nested(issue, "created_at")
            or _get_nested(issue, "createdAt")
            or _get_nested(issue, "first_seen")
            or _get_nested(issue, "timestamp")
        )
        first_detected_at = None
        if first_detected_raw:
            if isinstance(first_detected_raw, str) and first_detected_raw.strip():
                first_detected_at = first_detected_raw.strip()
            elif hasattr(first_detected_raw, "isoformat"):
                first_detected_at = first_detected_raw.isoformat()
            elif isinstance(first_detected_raw, (int, float)):
                ts = float(first_detected_raw)
                if ts > 1e12:  # milliseconds
                    ts = ts / 1000
                first_detected_at = datetime.fromtimestamp(
                    ts, tz=timezone.utc
                ).isoformat()

        # Map Aikido status (open, ignored, closed) to VAT status
        # Check ignored FIRST: Aikido may set closed_at when ignoring; ignored = Suppressed, not Resolved
        aikido_status = str(_get_nested(issue, "status") or "").lower()
        ignored_at = _get_nested(issue, "ignored_at") or _get_nested(issue, "ignoredAt")
        closed_at_raw = _get_nested(issue, "closed_at") or _get_nested(
            issue, "closedAt"
        )
        if ignored_at or aikido_status in ("ignored", "suppressed", "auto_ignored"):
            status = "Suppressed"
        elif closed_at_raw or aikido_status in ("closed", "resolved"):
            status = "Resolved"
        else:
            status = "Open"

        closed_at_iso = None
        if closed_at_raw:
            if isinstance(closed_at_raw, str) and closed_at_raw.strip():
                closed_at_iso = closed_at_raw.strip()
            elif hasattr(closed_at_raw, "isoformat"):
                closed_at_iso = closed_at_raw.isoformat()
            elif isinstance(closed_at_raw, (int, float)):
                ts = float(closed_at_raw)
                if ts > 1e12:
                    ts = ts / 1000
                closed_at_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        # component_base: strip version (handles name@version and "name version")
        comp_base = extract_component_base(comp) if comp else None
        # ecosystem: for SCA/License, infer when Aikido does not provide
        ecosystem_val = (
            _get_nested(issue, "ecosystem")
            or _get_nested(issue, "package_manager")
            or _get_nested(issue, "packageManager")
        )
        if ecosystem_val and isinstance(ecosystem_val, str) and ecosystem_val.strip():
            ecosystem_val = ecosystem_val.strip()
        elif finding_type in (VatFindingType.SCA, VatFindingType.LICENSE) and comp:
            ecosystem_val = _infer_ecosystem(issue, comp, asset_name)

        ref_for_digest = ""
        if isinstance(asset_name, str) and asset_name.strip():
            ref_for_digest = asset_name.strip()
        elif raw_asset and isinstance(raw_asset, str) and raw_asset.strip():
            ref_for_digest = raw_asset.strip()
        image_digest_val = _extract_image_digest_from_issue(
            issue, ref_for_digest or None
        )

        observed_container_tags: list[str] | None = None
        if is_container and asset_name:
            collected = _collect_container_tags_from_issue(issue)
            if collected:
                merged: list[str] = []
                mseen: set[str] = set()
                if tag:
                    mseen.add(tag)
                    merged.append(tag)
                for t in collected:
                    if t not in mseen:
                        mseen.add(t)
                        merged.append(t)
                observed_container_tags = merged
            elif tag:
                observed_container_tags = [tag]

        license_expression: str | None = None
        if finding_type == VatFindingType.LICENSE:
            license_expression = _normalize_aikido_license_type(
                _get_nested(issue, "license_type")
                or _get_nested(issue, "licenseType")
            )

        return VatFindingSchema(
            cve_id=cve_id,
            severity=sev,
            description=desc,
            component=comp or None,
            component_base=comp_base or None,
            ecosystem=ecosystem_val,
            title=str(title),
            finding_type=finding_type,
            image=asset_name,
            image_digest=image_digest_val,
            branch=branch,
            tag=tag,
            observed_container_tags=observed_container_tags,
            source_issue_id=source_issue_id,
            source_issue_url=source_issue_url,
            source_issue_group_id=source_issue_group_id,
            status=status,
            team=_get_nested(issue, "team") or _get_nested(issue, "project"),
            owner=_get_nested(issue, "owner") or _get_nested(issue, "assignee"),
            cvss=str(cvss_raw) if cvss_raw is not None else None,
            epss=str(_get_nested(issue, "epss"))
            if _get_nested(issue, "epss") is not None
            else None,
            source_file_url=source_file_url,
            file_path=file_path,
            line=line,
            first_detected_at=first_detected_at,
            closed_at=closed_at_iso,
            license_expression=license_expression,
        )

    async def ignore_issue(self, request: VatSourceIgnoreRequest) -> None:
        """Tell Aikido to ignore this issue. scope: global (FP) | contextual (Suppressed)."""
        await ignore_issue_aikido(request.issue_id, request.scope, self._credentials)

    async def unignore_issue(self, request: VatSourceUnignoreRequest) -> None:
        """Tell Aikido to unignore this issue (e.g. on Reopened)."""
        await unignore_issue_aikido(request.issue_id, self._credentials)


def _get_base_url(region: str) -> str:
    """Return Aikido API base URL for region (eu, us, me). Override via config for testing."""
    s = get_settings()
    if s.aikido_base_url:
        return s.aikido_base_url.rstrip("/")
    r = (region or "eu").lower()
    return REGION_BASE_URLS.get(r, REGION_BASE_URLS["eu"])


async def _get_oauth_token(client_id: str, client_secret: str, region: str) -> str:
    """Exchange client credentials for access token. Caches token until ~1min before expiry."""
    import base64
    import time

    cache_key = f"{region}:{client_id}"
    cached = _token_cache.get(cache_key)
    if cached and time.time() < cached[1] - 60:
        return cached[0]

    base_url = _get_base_url(region)
    token_url = f"{base_url}/api/oauth/token"
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    client = _aikido_client()
    resp = await client.post(
        token_url,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        content="grant_type=client_credentials",
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()

    token = data["access_token"]
    expires_in = data.get("expires_in", 3600)
    _token_cache[cache_key] = (token, time.time() + expires_in)
    return token


async def fetch_aikido_issues(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """
    Bootstrap: fetch all issues from Aikido GET /issues/export.
    API: https://apidocs.aikido.dev/reference/exportissues
    Returns a list of all issues (open, ignored, snoozed, closed, ...) in one response.
    Response: array or { issues: [...] } or { data: [...] }.
    """
    s = get_settings()
    creds = credentials or {}
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = (creds.get("region") or s.aikido_region or "eu").lower()

    if not (client_id and client_secret):
        raise ValueError(
            "Aikido credentials not configured. Set client_id and client_secret (OAuth). "
            "See VAT_AIKIDO_CLIENT_ID, VAT_AIKIDO_CLIENT_SECRET, VAT_AIKIDO_REGION."
        )

    token = await _get_oauth_token(client_id, client_secret, region)
    base_url = _get_base_url(region)
    export_url = f"{base_url}/api/public/v1/issues/export"

    client = _aikido_client()
    max_retries = 3
    for attempt in range(max_retries):
        await _acquire_rate_limit_slot()
        resp = await client.get(
            export_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=120.0,
        )
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_after)
                continue
            resp.raise_for_status()
        resp.raise_for_status()
        data = resp.json()
        break
    # Aikido may return { issues: [...] } or direct array
    if isinstance(data, list):
        return data
    return data.get("issues", data.get("data", []))


async def _aikido_api_get(
    path: str,
    credentials: Optional[dict[str, Any]] = None,
) -> Any:
    """GET request to Aikido API. Returns JSON response. Rate-limited with 429 retry."""
    s = get_settings()
    creds = credentials or {}
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = (creds.get("region") or s.aikido_region or "eu").lower()
    if not (client_id and client_secret):
        raise ValueError("Aikido credentials not configured")
    token = await _get_oauth_token(client_id, client_secret, region)
    base_url = _get_base_url(region)
    url = f"{base_url}/api/public/v1{path}"

    client = _aikido_client()
    max_retries = 3
    for attempt in range(max_retries):
        await _acquire_rate_limit_slot()
        resp = await client.get(
            url, headers={"Authorization": f"Bearer {token}"}, timeout=60.0
        )
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_after)
                continue
            resp.raise_for_status()
        resp.raise_for_status()
        return resp.json()


async def _aikido_api_get_maybe_json(
    path: str,
    credentials: Optional[dict[str, Any]] = None,
    *,
    timeout: float = 120.0,
) -> Any | None:
    """
    Authenticated GET that returns JSON/text or None on failure.
    For some Aikido endpoints (e.g. /containers/{id}/licenses/export), successful
    responses may be CSV text instead of JSON.
    Uses the same OAuth and rate limiting as other Aikido calls.
    """
    s = get_settings()
    creds = credentials or {}
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = (creds.get("region") or s.aikido_region or "eu").lower()
    if not (client_id and client_secret):
        return None
    try:
        token = await _get_oauth_token(client_id, client_secret, region)
        base_url = _get_base_url(region)
        url = f"{base_url}/api/public/v1{path}"
        await _acquire_rate_limit_slot()
        client = _aikido_client()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        resp = await client.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 429:
            await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
            await _acquire_rate_limit_slot()
            resp = await client.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return None
        if not (resp.content or b"").strip():
            return None
        try:
            return resp.json()
        except Exception:
            # Fallback to text payload for non-JSON exports (CSV)
            text = (resp.text or "").strip()
            return text or None
    except Exception as e:
        logger.debug("Aikido optional GET %s failed: %s", path, e)
        return None


def _normalize_aikido_container_id_list(
    container_repo_ids: list[Any],
) -> list[int | str]:
    ids: list[int | str] = []
    for x in container_repo_ids or []:
        if isinstance(x, int):
            ids.append(x)
            continue
        s = str(x).strip()
        if s.isdigit():
            ids.append(int(s))
        elif s:
            ids.append(s)
    return ids


def _sbom_bulk_generate_body_variants(
    ids: list[int | str],
    *,
    extended: bool = False,
) -> list[tuple[str, dict[str, Any]]]:
    """Label + JSON body for POST /containers/sbom/generate (schema varies by API version)."""
    core: list[tuple[str, dict[str, Any]]] = [
        ("container_ids", {"container_ids": ids}),
        ("containerIds", {"containerIds": ids}),
        ("ids", {"ids": ids}),
    ]
    if not extended:
        return core
    return [
        *core,
        ("repository_ids", {"repository_ids": ids}),
        ("container_repository_ids", {"container_repository_ids": ids}),
        (
            "containers[{id}]",
            {"containers": [{"id": i} for i in ids]},
        ),
    ]


async def _aikido_api_post_request(
    path: str,
    json_body: dict[str, Any],
    credentials: Optional[dict[str, Any]] = None,
    *,
    timeout: float = 180.0,
) -> tuple[int, str, str, Any | None]:
    """
    Authenticated POST. Returns
    ``(status_code, content_type, body_snippet, parsed_json_or_none)``.
    """
    s = get_settings()
    creds = credentials or {}
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = (creds.get("region") or s.aikido_region or "eu").lower()
    if not (client_id and client_secret):
        return 0, "", "", None
    try:
        token = await _get_oauth_token(client_id, client_secret, region)
        base_url = _get_base_url(region)
        url = f"{base_url}/api/public/v1{path}"
        await _acquire_rate_limit_slot()
        client = _aikido_client()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, */*",
            "Content-Type": "application/json",
        }
        resp = await client.post(url, headers=headers, json=json_body, timeout=timeout)
        if resp.status_code == 429:
            await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
            await _acquire_rate_limit_slot()
            resp = await client.post(
                url, headers=headers, json=json_body, timeout=timeout
            )
        ct = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        raw_bytes = resp.content or b""
        snippet = ""
        if raw_bytes.strip():
            try:
                snippet = (resp.text or "")[:1200]
            except Exception:
                snippet = f"<non-text body, {len(raw_bytes)} bytes>"
        parsed: Any | None = None
        if raw_bytes.strip():
            try:
                parsed = resp.json()
            except Exception:
                try:
                    parsed = json.loads(resp.text)
                except Exception:
                    parsed = None
        return resp.status_code, ct, snippet, parsed
    except Exception as e:
        logger.debug("Aikido POST %s failed: %s", path, e)
        return 0, "", str(e)[:500], None


async def diagnose_aikido_sbom_bulk_generate(
    container_repo_ids: list[Any],
    credentials: dict[str, Any],
    *,
    stream: Optional[TextIO] = None,
) -> None:
    """
    Print HTTP outcomes for each request-body variant (for ``verify_aikido_sbom_live``).
    Uses at most 5 ids to limit rate-limit noise.
    """
    import sys

    out = stream or sys.stderr
    ids = _normalize_aikido_container_id_list(container_repo_ids)
    if not ids:
        print("  diagnose: no container ids", file=out)
        return
    sample = ids[:5]
    print(
        f"  diagnose: POST .../containers/sbom/generate with {len(sample)} id(s) "
        f"(showing body-shape attempts)",
        file=out,
    )
    for label, body in _sbom_bulk_generate_body_variants(sample, extended=True):
        status, ct, snippet, data = await _aikido_api_post_request(
            "/containers/sbom/generate",
            body,
            credentials,
            timeout=180.0,
        )
        keys = ""
        if isinstance(data, dict):
            keys = f" json_keys={sorted(data.keys())[:12]}"
        elif data is not None:
            keys = f" json_type={type(data).__name__}"
        print(f"    {label}: HTTP {status} content-type={ct!r}{keys}", file=out)
        if snippet and not isinstance(data, dict):
            print(f"      snippet: {snippet[:500]!r}", file=out)
        elif snippet and isinstance(data, dict) and "bomFormat" not in data:
            print(f"      snippet: {snippet[:400]!r}", file=out)


async def fetch_aikido_containers_sbom_bulk_generate(
    container_repo_ids: list[Any],
    credentials: Optional[dict[str, Any]] = None,
) -> Any | None:
    """
    POST /containers/sbom/generate — bulk SBOM for the given container repo ids.

    When per-container ``GET /containers/{id}/licenses/export`` returns empty, this endpoint
    may still produce CycloneDX (see Aikido API docs).

    https://apidocs.aikido.dev/reference/generatecontainersbom
    """
    ids = _normalize_aikido_container_id_list(container_repo_ids)
    if not ids:
        return None
    for label, body in _sbom_bulk_generate_body_variants(ids, extended=False):
        status, ct, snippet, data = await _aikido_api_post_request(
            "/containers/sbom/generate",
            body,
            credentials,
            timeout=180.0,
        )
        if 200 <= status < 300 and data is not None:
            logger.debug(
                "Aikido bulk SBOM: used body %s status=%s content-type=%s",
                label,
                status,
                ct,
            )
            return data
        logger.debug(
            "Aikido bulk SBOM: body %s status=%s content-type=%s snippet=%s",
            label,
            status,
            ct,
            (snippet or "")[:200],
        )
    return None


async def fetch_aikido_container_licenses_export(
    container_repo_id: str | int,
    credentials: Optional[dict[str, Any]] = None,
) -> Any | None:
    """
    GET /containers/{container_repo_id}/licenses/export — license/SBOM payload.

    Aikido supports query param ``format`` with values including:
    - ``sbom`` (CycloneDX JSON)
    - ``sbom_spdx`` (SPDX JSON)
    - ``csv`` (default CSV export)

    We prefer ``format=sbom`` so downstream identity parsing can read digest/tag from
    CycloneDX metadata.

    Returns parsed JSON or None. Does not raise on 404 or parse errors.
    API: https://apidocs.aikido.dev/reference/exportcontainerrepolicenses
    """
    cid = str(container_repo_id).strip()
    if not cid:
        return None
    # Prefer CycloneDX JSON SBOM.
    for path in (
        f"/containers/{cid}/licenses/export?format=sbom",
        f"/containers/{cid}/licenses/export?format=sbom_spdx",
        f"/containers/{cid}/licenses/export",
    ):
        raw = await _aikido_api_get_maybe_json(
            path,
            credentials,
            timeout=120.0,
        )
        if raw is not None:
            return raw
    return None


async def fetch_aikido_code_repositories(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """
    Fetch code repositories from Aikido GET /repositories/code.
    Each repo may have id, name, branch. Used to map code_repo_id -> branch for issues.

    Paginated: the endpoint defaults to 20 per page, so an unpaged call silently
    truncates a workspace with more repos than that.
    """
    all_repos: list[dict[str, Any]] = []
    # Aikido list endpoints are zero-indexed, same as /containers.
    page = 0
    per_page = 100
    while True:
        data = await _aikido_api_get(
            f"/repositories/code?page={page}&per_page={per_page}", credentials
        )
        items = (
            data
            if isinstance(data, list)
            else data.get("repositories", data.get("data", data.get("items", [])))
        )
        if not items:
            break
        all_repos.extend(items)
        if len(items) < per_page:
            break
        page += 1
    return all_repos


async def _aikido_api_put(
    path: str,
    credentials: Optional[dict[str, Any]] = None,
    json_body: Optional[dict] = None,
) -> None:
    """PUT request to Aikido API. Used for ignore/unignore. Rate-limited with 429 retry."""
    s = get_settings()
    creds = credentials or {}
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = (creds.get("region") or s.aikido_region or "eu").lower()
    if not (client_id and client_secret):
        raise ValueError("Aikido credentials not configured")
    token = await _get_oauth_token(client_id, client_secret, region)
    base_url = _get_base_url(region)
    url = f"{base_url}/api/public/v1{path}"

    client = _aikido_client()
    max_retries = 3
    for attempt in range(max_retries):
        await _acquire_rate_limit_slot()
        kwargs: dict[str, Any] = {
            "headers": {"Authorization": f"Bearer {token}"},
            "timeout": 30.0,
        }
        if json_body is not None:
            kwargs["headers"]["Content-Type"] = "application/json"
            kwargs["json"] = json_body
        resp = await client.put(url, **kwargs)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_after)
                continue
            resp.raise_for_status()
        resp.raise_for_status()
        return


async def ignore_issue_aikido(
    issue_id: str, scope: str, credentials: Optional[dict] = None
) -> None:
    """Call Aikido ignore API. scope: global (FP) | contextual (Suppressed)."""
    path = f"/issues/{issue_id}/ignore"
    # Aikido API: PUT /issues/{id}/ignore. Body optional; omit if API doesn't support it.
    await _aikido_api_put(path, credentials, json_body=None)


async def unignore_issue_aikido(
    issue_id: str, credentials: Optional[dict] = None
) -> None:
    """Call Aikido unignore API."""
    path = f"/issues/{issue_id}/unignore"
    await _aikido_api_put(path, credentials)


# ---------------------------------------------------------------------------
# Dashboard data fetchers (matches vulnerability-dashboard)
# ---------------------------------------------------------------------------


async def _aikido_api_get_safe(
    path: str,
    credentials: Optional[dict[str, Any]] = None,
) -> Any:
    """GET request to Aikido API. Returns None on 404/403/5xx instead of raising."""
    try:
        return await _aikido_api_get(path, credentials)
    except Exception:
        return None


async def fetch_aikido_open_issue_groups(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch open issue groups from GET /open-issue-groups (paginated)."""
    all_groups: list[dict] = []
    page = 1
    per_page = 50
    while True:
        data = await _aikido_api_get_safe(
            f"/open-issue-groups?page={page}&per_page={per_page}",
            credentials,
        )
        if not data:
            break
        items = (
            data
            if isinstance(data, list)
            else data.get("groups", data.get("open_issue_groups", data.get("data", [])))
        )
        if not items:
            break
        all_groups.extend(items)
        if len(items) < per_page:
            break
        page += 1
    return all_groups


async def fetch_aikido_containers(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch containers from GET /containers (paginated)."""
    all_containers: list[dict] = []
    # Aikido list endpoints are zero-indexed (page starts at 0).
    # Starting at 1 silently drops the first page (up to 100 containers).
    page = 0
    per_page = 100
    while True:
        data = await _aikido_api_get_safe(
            f"/containers?page={page}&per_page={per_page}",
            credentials,
        )
        if not data:
            break
        items = (
            data
            if isinstance(data, list)
            else data.get("containers", data.get("repositories", data.get("data", [])))
        )
        if not items:
            break
        all_containers.extend(items)
        if len(items) < per_page:
            break
        page += 1
    return all_containers


async def fetch_aikido_virtual_machines(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch virtual machines from GET /virtual-machines."""
    data = await _aikido_api_get_safe("/virtual-machines", credentials)
    if not data:
        return []
    return (
        data
        if isinstance(data, list)
        else data.get(
            "virtual_machines",
            data.get("vms", data.get("machines", data.get("data", []))),
        )
    )


async def fetch_aikido_issue_counts(
    credentials: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Fetch issue counts from GET /issues/counts."""
    data = await _aikido_api_get_safe("/issues/counts", credentials)
    if not data:
        return None

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            if v is None:
                return default
            return int(v)
        except (TypeError, ValueError):
            return default

    d: dict[str, Any] = {}
    if isinstance(data, dict):
        # Aikido may return:
        # 1) {"counts": {...}}
        # 2) {"issues": {...}, "issue_groups": {...}}
        # 3) flat {"open":..., "critical":...}
        if isinstance(data.get("issues"), dict):
            d = data["issues"]
        elif isinstance(data.get("counts"), dict):
            d = data["counts"]
        else:
            d = data

    total = _as_int(d.get("total", d.get("nr_total", d.get("all", 0))), 0)
    # Some payloads only expose "all" (open issue count for current workspace scope).
    open_count = _as_int(d.get("open", d.get("nr_open", d.get("all", total))), total)
    return {
        "total": total,
        "open": open_count,
        "critical": _as_int(d.get("critical", d.get("nr_critical", 0)), 0),
        "high": _as_int(d.get("high", d.get("nr_high", 0)), 0),
        "medium": _as_int(d.get("medium", d.get("nr_medium", 0)), 0),
        "low": _as_int(d.get("low", d.get("nr_low", 0)), 0),
    }


async def fetch_aikido_activity_log(
    credentials: Optional[dict[str, Any]] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Fetch activity log from GET /report/activityLog."""
    data = await _aikido_api_get_safe("/report/activityLog", credentials)
    if not data:
        return []
    items = (
        data
        if isinstance(data, list)
        else (
            data.get("items")
            or data.get("activities")
            or data.get("data")
            or data.get("activity_log")
            or data.get("results")
            or []
        )
    )
    if not isinstance(items, list):
        return []
    return items[:limit]


async def fetch_aikido_ci_scans(
    credentials: Optional[dict[str, Any]] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Fetch CI scans from GET /report/ciScans."""
    data = await _aikido_api_get_safe("/report/ciScans", credentials)
    if not data:
        return []
    items = (
        data
        if isinstance(data, list)
        else (
            data.get("items")
            or data.get("scans")
            or data.get("data")
            or data.get("ci_scans")
            or data.get("results")
            or []
        )
    )
    if not isinstance(items, list):
        return []
    return items[:limit]


async def fetch_aikido_task_projects(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch task tracking projects from GET /task_tracking/projects."""
    data = await _aikido_api_get_safe("/task_tracking/projects", credentials)
    if not data:
        return []
    return (
        data
        if isinstance(data, list)
        else data.get("projects", data.get("items", data.get("data", [])))
    )


# Disabled: not used in sync; reachabilityByIssueId is always {} in dashboard data
async def fetch_aikido_issue_reachability(
    issue_id: int,
    credentials: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Fetch reachability for a single issue from GET /issues/{id}/reachability."""
    data = await _aikido_api_get_safe(f"/issues/{issue_id}/reachability", credentials)
    if not data or not isinstance(data, dict):
        return None
    return {
        "issue_id": issue_id,
        "reachable": data.get("reachable", False),
        "exploitable": data.get("exploitable", False),
        **data,
    }


async def fetch_aikido_reachability_for_issues(
    issue_ids: list[int],
    credentials: Optional[dict[str, Any]] = None,
    max_issues: int = 20,
) -> dict[int, dict]:
    """Fetch reachability for top N issues (sequential to avoid rate limits)."""
    result: dict[int, dict] = {}
    for iid in issue_ids[:max_issues]:
        r = await fetch_aikido_issue_reachability(iid, credentials)
        if r:
            result[iid] = r
    return result


async def fetch_aikido_issue_group_tasks(
    group_id: int,
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch tasks linked to an issue group. Tries both /issues/groups/{id}/tasks and /issues/group/{id}/tasks."""
    for path in [f"/issues/groups/{group_id}/tasks", f"/issues/group/{group_id}/tasks"]:
        data = await _aikido_api_get_safe(path, credentials)
        if not data:
            continue
        items = (
            data
            if isinstance(data, list)
            else (
                data.get("tasks")
                or data.get("items")
                or data.get("data")
                or data.get("linked_tasks")
                or []
            )
        )
        if isinstance(items, list):
            return items
    return []


async def fetch_aikido_tasks_for_groups(
    group_ids: list[int],
    credentials: Optional[dict[str, Any]] = None,
    max_groups: int = 15,
) -> dict[int, list]:
    """Fetch tasks for top N issue groups."""
    result: dict[int, list] = {}
    for gid in group_ids[:max_groups]:
        tasks = await fetch_aikido_issue_group_tasks(gid, credentials)
        if tasks:
            result[gid] = tasks
    return result


async def fetch_aikido_cve_details(
    cve_id: str,
    credentials: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Fetch CVE details (EPSS, KEV) from GET /cve/{id} or /research/cve/{id}."""
    if not cve_id or str(cve_id).strip().upper() == "N/A":
        return None
    normalized = str(cve_id).replace("CVE-", "").replace("cve-", "").strip()
    if not normalized:
        return None
    for path in [f"/cve/{normalized}", f"/research/cve/{normalized}"]:
        data = await _aikido_api_get_safe(path, credentials)
        if data and isinstance(data, dict):
            return {
                "id": data.get("id", data.get("cve_id", cve_id)),
                "epss_score": data.get("epss_score"),
                "in_kev": data.get("in_kev") or data.get("kev", False),
                "published_at": data.get("published_at"),
                **data,
            }
    return None


async def fetch_aikido_workspace(
    credentials: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Fetch workspace info from GET /workspace."""
    data = await _aikido_api_get_safe("/workspace", credentials)
    if not data or not isinstance(data, dict):
        return None
    return data


async def fetch_aikido_teams(
    credentials: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Fetch teams from GET /teams.

    Each team carries ``responsibilities``: ``{id, type}`` where type is
    ``code_repository`` or ``container_repository`` and ``id`` refers to a
    row from ``/repositories/code`` or ``/containers`` respectively.
    """
    # Raising, not _aikido_api_get_safe: swallowing an upstream error here
    # returns an empty list, and "no teams" is indistinguishable from "Aikido
    # said 429". The route turns the exception into a real status the user can
    # act on.
    data = await _aikido_api_get("/teams", credentials)
    if not data:
        return []
    if isinstance(data, list):
        return data
    return data.get("teams", data.get("data", data.get("items", [])))


_TEAM_RESPONSIBILITY_SOURCES = {
    "code_repository": "code_repos",
    "container_repository": "containers",
}


def _team_member_context(source: str, member: dict[str, Any]) -> dict[str, Any]:
    """Branch context for a team member, in VAT's FavoriteEntry vocabulary.

    Only code repos get context here, and only their branch ("develop",
    "release/1.2.1") — that is a real, stable property of the responsibility.

    Containers deliberately get nothing. Aikido's container ``tag`` is transient
    (it read "pr-209" for an image whose observed tags were release-1.2.1,
    latest and develop) and the dashboard cache stores a reduced container
    projection with no tag fields at all, so reading it made the same request
    answer differently depending on cache freshness. The caller picks a
    container's tag from the tags VAT has actually observed, matched against
    the team's branch — see resolveTeamEntries.
    """
    if source != "code_repos":
        return {}
    branch = member.get("branch")
    return {"branch": branch.strip()} if isinstance(branch, str) and branch.strip() else {}


def aikido_teams_to_asset_names(
    teams: list[dict[str, Any]],
    code_repos: list[dict[str, Any]],
    containers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve each team's responsibilities to its members, with branch/tag context.

    Member names are returned as Aikido reports them. VAT asset ids are derived on
    the frontend and carry a registry prefix Aikido omits (``docker.io/ns/images/x``
    vs ``ns/images/x``), so normalization is left to the caller that owns asset
    identity. ``unresolved`` counts responsibilities whose id was not in the
    repo/container lists — usually an inactive or since-deleted resource.
    """
    by_source = {
        "code_repos": {r.get("id"): r for r in code_repos or [] if isinstance(r, dict)},
        "containers": {c.get("id"): c for c in containers or [] if isinstance(c, dict)},
    }
    out: list[dict[str, Any]] = []
    for team in teams or []:
        if not isinstance(team, dict):
            continue
        members: list[dict[str, Any]] = []
        seen: set[tuple] = set()
        unresolved = 0
        for resp in team.get("responsibilities") or []:
            if not isinstance(resp, dict):
                continue
            source = _TEAM_RESPONSIBILITY_SOURCES.get(resp.get("type"))
            member = by_source[source].get(resp.get("id")) if source else None
            name = (member or {}).get("name")
            if not (isinstance(name, str) and name.strip()):
                unresolved += 1
                continue
            entry = {"name": name.strip(), **_team_member_context(source, member)}
            # A repo appears once per branch, so dedupe on the whole context —
            # keeping "containers@develop" and "containers@release/1.2.1" apart.
            key = (entry["name"], entry.get("branch"), entry.get("tag"))
            if key in seen:
                continue
            seen.add(key)
            members.append(entry)
        out.append(
            {
                "id": str(team.get("id")),
                "name": (team.get("name") or f"team-{team.get('id')}").strip(),
                "active": bool(team.get("active", True)),
                "members": members,
                "unresolved": unresolved,
            }
        )
    return out
