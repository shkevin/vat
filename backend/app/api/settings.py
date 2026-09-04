"""Settings API — sources, tracker, labels, ingest keys. PRD §5.9.1."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_admin
from app.core.config import get_settings as get_config
from app.core.database import get_db
from app.models.settings_model import SettingsKV
from app.schemas.auth import UserContext
from app.services.admin_keys import create_admin_key, list_admin_keys, revoke_admin_key
from app.services.ingest_keys import create_key, list_keys, regenerate_key, revoke_key
from app.services.oauth_clients import (
    create_oauth_client,
    list_oauth_clients,
    revoke_oauth_client,
    rotate_oauth_client,
)

router = APIRouter()


def _utc_now_naive():
    """Naive UTC datetime for TIMESTAMP WITHOUT TIME ZONE columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


DEFAULT_SOURCES = "sources"
DEFAULT_TRACKER = "tracker"
DEFAULT_TRACKERS = "trackers"
DEFAULT_LABELS = "labels"
AIKIDO_CREDENTIALS = "aikido_credentials"
AIKIDO_CREDENTIALS_PREFIX = "aikido_credentials:"
LINEAR_CREDENTIALS = "linear_credentials"


class SettingsResponse(BaseModel):
    sources: list[dict]
    tracker: dict
    trackers: list[dict] = []
    labels: list[dict]


class IntegrationSchemasResponse(BaseModel):
    """Schema-driven settings canvas. Adapters declare their UI; VAT defines flow types."""

    sources: list[dict]
    trackers: list[dict]
    flow_types: dict[str, dict]


async def _get_json(db: AsyncSession, key: str, default: list | dict) -> list | dict:
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row and row.value is not None:
        return row.value
    return default


async def _get_credentials(db: AsyncSession, key: str) -> dict:
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return row.value
    return {}


def _aikido_creds_key(source_id: str | None) -> str:
    """Settings key for Aikido credentials. Per-source when source_id given."""
    return (
        f"{AIKIDO_CREDENTIALS_PREFIX}{source_id}" if source_id else AIKIDO_CREDENTIALS
    )


async def get_aikido_credentials(
    db: AsyncSession, source_id: str | None = None, *, strict: bool = False
) -> dict:
    """Return Aikido credentials from DB or env: client_id, client_secret,
    region, webhook_secret, tenant_id.

    When ``source_id`` is provided, uses per-source credentials. By default
    falls back to the legacy global key if per-source is empty (sync flows).

    ``strict=True`` disables that fallback — required for webhook handlers
    so a webhook signed by source Y's secret cannot be HMAC-validated
    against source X's by routing through the global creds. Returns an
    empty creds dict when strict and per-source is unconfigured.
    """
    s = get_config()
    creds: dict = {}
    if source_id:
        creds = await _get_credentials(db, _aikido_creds_key(source_id))
        per_source_present = bool(creds and (creds.get("client_id") or creds.get("clientId")))
        if not per_source_present:
            if strict:
                # Per-source webhook with no per-source creds — refuse to fall
                # back. Caller will emit 503; operator must configure the
                # source explicitly before its webhook URL is reachable.
                return {
                    "client_id": None,
                    "client_secret": None,
                    "region": s.aikido_region or "eu",
                    "webhook_secret": None,
                    "tenant_id": None,
                    "sync_back_enabled": True,
                }
            creds = await _get_credentials(db, AIKIDO_CREDENTIALS)
    else:
        creds = await _get_credentials(db, AIKIDO_CREDENTIALS)
    return {
        "client_id": creds.get("client_id")
        or creds.get("clientId")
        or s.aikido_client_id,
        "client_secret": creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret,
        "region": creds.get("region") or s.aikido_region or "eu",
        "webhook_secret": creds.get("webhook_secret")
        or creds.get("webhookSecret")
        or s.aikido_webhook_secret,
        # Tenant binding for webhook ingest (M16). Per-source creds can
        # carry tenant_id / tenantId; absent for legacy global config.
        # Passed into ingest_finding so the resulting Finding row is
        # tenant-scoped from the get-go instead of NULL-tenant (which the
        # tenant_filter helper now refuses to surface).
        "tenant_id": creds.get("tenant_id") or creds.get("tenantId"),
        "sync_back_enabled": creds.get("sync_back_enabled", True),
    }


DEFAULT_ISSUE_TEMPLATE = """[VAT] {finding_id}

---
### Vulnerability Assessment Response
Post the block below as a **comment** to update this finding in VAT.

| Field | Value |
|-------|-------|
| status | `false-positive` \\| `not-applicable` \\| `risk-accepted` \\| `mitigated` \\| `duplicate` |
| justification | _(required — explain why; cite evidence for false-positive)_ |
| compensating-controls | _(optional — e.g. WAF, network segmentation, monitoring)_ |

**Copy-paste and fill in:**
```
[VAT] {finding_id}
status:
justification:
compensating-controls:
```
"""


async def get_tracker_issue_template(db: AsyncSession) -> str:
    """Return the issue template from primary tracker config, or default."""
    trackers = await _get_trackers(db)
    tracker = trackers[0] if trackers else {}
    if isinstance(tracker, dict) and tracker.get("issueTemplate"):
        return str(tracker["issueTemplate"])
    return DEFAULT_ISSUE_TEMPLATE


async def get_labels(db: AsyncSession) -> list[dict]:
    """Return configured labels (applied when creating Linear issues). Default: security-bug."""
    labels = await _get_json(db, DEFAULT_LABELS, [])
    if isinstance(labels, list):
        out = [l for l in labels if isinstance(l, dict) and l.get("name")]
        if out:
            return out
    return [{"name": "security-bug", "color": "#E53935"}]


def labels_to_configs(labels_cfg: list[dict]) -> list["LabelConfig"]:
    """Build LabelConfig list from settings labels (for color when auto-creating)."""
    from app.schemas.vat import LabelConfig

    return [
        LabelConfig(name=l["name"], color=l.get("color"))
        for l in labels_cfg
        if isinstance(l, dict) and l.get("name")
    ]


def _tracker_adapter_key(t: dict) -> str:
    """Extract adapter/type from tracker dict. Default: linear."""
    return (t.get("adapter") or t.get("type") or "linear").lower()


async def _get_trackers(db: AsyncSession) -> list[dict]:
    """Return trackers list. Migrates from single tracker on first read."""
    trackers = await _get_json(db, DEFAULT_TRACKERS, [])
    if isinstance(trackers, list) and len(trackers) > 0:
        return trackers
    tracker = await _get_json(db, DEFAULT_TRACKER, {})
    if isinstance(tracker, dict) and tracker:
        t = dict(tracker)
        if not t.get("id"):
            t["id"] = "t-default"
        return [t]
    return []


async def get_tracker_key(db: AsyncSession) -> str:
    """Return adapter key for primary VAT tracker (credential lookup, create_issue). Default: linear."""
    trackers = await _get_trackers(db)
    for t in trackers:
        if not t.get("useAikidoTracking") and not t.get("use_aikido_tracking"):
            return _tracker_adapter_key(t)
    if trackers:
        return _tracker_adapter_key(trackers[0])
    return "linear"


async def get_tracker_key_for_source(
    db: AsyncSession, aikido_source_id: str
) -> str | None:
    """Return tracker key for Aikido source when useAikidoTracking. Used for external_links adapter_key. None if no match."""
    trackers = await _get_trackers(db)
    for t in trackers:
        if not (t.get("useAikidoTracking") or t.get("use_aikido_tracking")):
            continue
        sid = (t.get("sourceId") or t.get("source_id") or "").strip()
        if sid == aikido_source_id:
            return t.get("id") or f"linear-{aikido_source_id}"
    return None


# Required credential keys per tracker adapter. Extend when adding new trackers (e.g. jira).
TRACKER_REQUIRED_CREDENTIALS: dict[str, list[str]] = {
    "linear": ["api_key", "team_id"],
}


def is_tracker_configured_for_creds(tracker_key: str, creds: dict) -> bool:
    """True if creds contain all required keys for the tracker. Tracker-agnostic."""
    keys = TRACKER_REQUIRED_CREDENTIALS.get((tracker_key or "").lower(), [])
    if not keys:
        return False
    return all(creds.get(k) for k in keys)


async def get_use_aikido_tracking(db: AsyncSession) -> bool:
    """True when any tracker has useAikidoTracking. VAT skips create_issue for Aikido findings."""
    trackers = await _get_trackers(db)
    return any(
        t.get("useAikidoTracking") or t.get("use_aikido_tracking")
        for t in trackers
        if isinstance(t, dict)
    )


async def get_tracker_push_mode(db: AsyncSession) -> str:
    """
    Return push mode: 'groups' (one ticket per CVE/title, deduplicate) or 'instances' (one ticket per finding).
    Default: groups.
    """
    trackers = await _get_trackers(db)
    tracker = trackers[0] if trackers else {}
    if isinstance(tracker, dict):
        mode = (tracker.get("pushMode") or tracker.get("push_mode") or "groups").lower()
        return mode if mode in ("groups", "instances") else "groups"
    return "groups"


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def _severity_order(sev: str) -> int:
    """0=Critical (highest), 4=Informational (lowest). Unknown = 4 (lowest)."""
    s = (sev or "").lower().strip()
    try:
        return _SEVERITY_ORDER.index(s)
    except ValueError:
        return 4


async def get_tracker_push_min_severity(db: AsyncSession) -> str | None:
    """
    Return minimum severity to push: 'critical', 'high', 'medium', 'low', 'informational', or None/'all' for all.
    E.g. 'high' = push Critical and High only. Default: None (push all severities).
    """
    trackers = await _get_trackers(db)
    tracker = trackers[0] if trackers else {}
    if isinstance(tracker, dict):
        val = (
            (
                tracker.get("pushMinSeverity")
                or tracker.get("push_min_severity")
                or "all"
            )
            .lower()
            .strip()
        )
        if not val or val == "all":
            return None
        if val in _SEVERITY_ORDER:
            return val
    return None


def severity_meets_min(severity: str, min_severity: str | None) -> bool:
    """True if finding severity is at or above min_severity. min_severity=None means all pass."""
    if not min_severity:
        return True
    return _severity_order(severity) <= _severity_order(min_severity)


async def has_aikido_source_on_canvas(db: AsyncSession) -> bool:
    """True if at least one Aikido source exists in the integration canvas (sources config)."""
    sources = await _get_json(db, DEFAULT_SOURCES, [])
    if not isinstance(sources, list):
        return False
    return any(
        isinstance(s, dict) and (s.get("adapter") or "").lower() == "aikido"
        for s in sources
    )


async def first_aikido_source_id(db: AsyncSession) -> str | None:
    """Id of the first Aikido source on the canvas.

    Lets callers omit source_id in the common single-source setup.
    """
    sources = await _get_json(db, DEFAULT_SOURCES, [])
    if not isinstance(sources, list):
        return None
    for s in sources:
        if (
            isinstance(s, dict)
            and (s.get("adapter") or "").lower() == "aikido"
            and s.get("id")
        ):
            return str(s["id"])
    return None


async def get_source_config(db: AsyncSession, source_name: str) -> dict | None:
    """Return source config by name. Used for supports_outbound_sync.
    Fallback: Aikido defaults to adapter aikido, supportsOutboundSync from credentials."""
    sources = await _get_json(db, DEFAULT_SOURCES, [])
    if isinstance(sources, list):
        for s in sources:
            if isinstance(s, dict) and (
                s.get("id") == source_name or s.get("name") == source_name
            ):
                out = dict(s)
                if (out.get("adapter") or "").lower() == "aikido":
                    creds = await get_aikido_credentials(db, out.get("id"))
                    out["supportsOutboundSync"] = bool(
                        creds.get("sync_back_enabled", True)
                    )
                return out
    if source_name and source_name.lower() == "aikido":
        creds = await get_aikido_credentials(db, None)
        sync_back = creds.get("sync_back_enabled", True)
        return {"adapter": "aikido", "supportsOutboundSync": bool(sync_back)}
    return None


_PLACEHOLDER_PATTERNS = ("placeholder", "demo-", "changeme", "xxx", "your-", "example")


def _is_placeholder(val: str | None) -> bool:
    """Treat demo/placeholder values as not configured."""
    if not val or not isinstance(val, str):
        return True
    v = val.lower().strip()
    return any(p in v for p in _PLACEHOLDER_PATTERNS)


async def get_linear_credentials(
    db: AsyncSession,
) -> tuple[str | None, str | None, str | None]:
    """Return (api_key, team_id, webhook_secret) from DB or env.
    DB takes precedence; env fallback when DB row is empty (e.g. .env or docker-compose).
    Placeholder values (demo-, placeholder, etc.) are treated as not configured."""
    s = get_config()
    creds = await _get_credentials(db, LINEAR_CREDENTIALS)
    db_api = creds.get("api_key") or creds.get("apiKey")
    db_team = creds.get("team_id") or creds.get("teamId")
    api_key = db_api or s.linear_api_key
    team_id = db_team or s.linear_team_id
    if not api_key or not team_id:
        return (None, None, None)
    if _is_placeholder(api_key) or _is_placeholder(team_id):
        return (None, None, None)
    webhook_secret = (
        creds.get("webhook_secret")
        or creds.get("webhookSecret")
        or s.linear_webhook_secret
    )
    return (api_key, team_id, webhook_secret)


def _get_integration_schemas() -> dict:
    """Collect settings schemas from registered adapters and VAT flow types."""
    from app.adapters import aikido, linear  # noqa: F401 — ensure adapters registered
    from app.adapters.registry import SOURCE_ADAPTER_REGISTRY, TRACKER_ADAPTER_REGISTRY
    from app.schemas.integration_ui import FLOW_TYPES

    sources = []
    for key, cls in SOURCE_ADAPTER_REGISTRY.items():
        schema_fn = getattr(cls, "get_settings_schema", None)
        if schema_fn and callable(schema_fn):
            schema = schema_fn()
            sources.append(schema.model_dump())

    trackers = []
    for key, cls in TRACKER_ADAPTER_REGISTRY.items():
        schema_fn = getattr(cls, "get_settings_schema", None)
        if schema_fn and callable(schema_fn):
            schema = schema_fn()
            trackers.append(schema.model_dump())

    flow_types = {k: v.model_dump() for k, v in FLOW_TYPES.items()}
    return {"sources": sources, "trackers": trackers, "flow_types": flow_types}


@router.get("/integration-schemas", response_model=IntegrationSchemasResponse)
async def get_integration_schemas(
    _ctx: UserContext = Depends(require_admin),
):
    """Get settings UI schemas for all registered integrations. Admin only.
    Frontend uses this to render schema-driven settings forms."""
    data = _get_integration_schemas()
    return IntegrationSchemasResponse(**data)


async def _get_linear_issue_base_url(db: AsyncSession) -> str | None:
    """Resolve Linear team to organization urlKey and return issue base URL. Returns None on failure."""
    creds = await _get_credentials(db, LINEAR_CREDENTIALS)
    s = get_config()
    api_key = creds.get("api_key") or s.linear_api_key
    team_id = creds.get("team_id") or s.linear_team_id
    if not api_key or not team_id:
        return None
    try:
        from app.adapters.linear import LinearAdapter, get_organization_url_key

        adapter = LinearAdapter(api_key=api_key, team_id=team_id)
        url_key = await get_organization_url_key(adapter)
        if url_key:
            return f"https://linear.app/{url_key}/issue/"
    except Exception:
        pass
    return None


DEFAULT_LABEL_SECURITY_BUG = {
    "id": "default-security-bug",
    "name": "security-bug",
    "color": "#E53935",
    "description": "",
}


@router.get("", response_model=SettingsResponse)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Get sources, trackers, and labels config. Admin only. tracker = primary (first non-Aikido or first)."""
    sources = await _get_json(db, DEFAULT_SOURCES, [])
    trackers = await _get_trackers(db)
    labels = await _get_json(db, DEFAULT_LABELS, [])
    if not labels or not isinstance(labels, list) or len(labels) == 0:
        labels = [dict(DEFAULT_LABEL_SECURITY_BUG)]
    else:
        out = []
        for l in labels:
            if not isinstance(l, dict) or not l.get("name"):
                continue
            item = dict(l)
            if not item.get("color"):
                item["color"] = (
                    "#E53935"
                    if (item.get("name") or "").lower() == "security-bug"
                    else "#E53935"
                )
            if not item.get("id"):
                item["id"] = "l-" + (item.get("name") or "").lower().replace(" ", "-")
            out.append(item)
        labels = out if out else [dict(DEFAULT_LABEL_SECURITY_BUG)]

    base_url = await _get_linear_issue_base_url(db)
    enriched: list[dict] = []
    for t in trackers:
        t = dict(t)
        if (
            t.get("type") or t.get("adapter") or "linear"
        ).lower() == "linear" and base_url:
            t["baseUrl"] = base_url
        if not t.get("type") and not t.get("adapter"):
            t["type"] = "linear"
        enriched.append(t)

    # Primary tracker for backward compat: first non-Aikido, else first
    primary = {}
    for t in enriched:
        if not (t.get("useAikidoTracking") or t.get("use_aikido_tracking")):
            primary = t
            break
    if not primary and enriched:
        primary = enriched[0]

    return SettingsResponse(
        sources=sources, tracker=primary, trackers=enriched, labels=labels
    )


class ManualSourceEnsureRequest(BaseModel):
    """Create or ensure a Manual source for a parser. 1:1 mapping: one source per parser."""

    parser: str = "trivy"
    source_id_prefix: str | None = Field(default="folder-scan", alias="sourceIdPrefix")
    asset_type: str | None = Field(default="package", alias="assetType")
    create_key: bool = Field(default=False, alias="createKey")
    regenerate_key: bool = Field(default=False, alias="regenerateKey")

    model_config = {"populate_by_name": True}


@router.post("/sources/manual/ensure")
async def post_sources_manual_ensure(
    body: ManualSourceEnsureRequest,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """
    Ensure a Manual source exists for the given parser. Creates source + key if missing.
    1:1 mapping: one source per parser (e.g. folder-scan-trivy, folder-scan-grype).
    Admin only.
    """
    parser = (body.parser or "trivy").strip().lower()
    raw_prefix = (
        body.source_id_prefix if body.source_id_prefix is not None else "folder-scan"
    )
    prefix = str(raw_prefix).strip()
    source_id = parser if not prefix else f"{prefix}-{parser}"
    name = f"Folder Scan ({parser})"
    asset_type = (body.asset_type or "package").strip().lower()

    from app.parsers import PARSER_REGISTRY

    if parser not in PARSER_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown parser: {parser}. Available: {list(PARSER_REGISTRY.keys())}",
        )

    sources = await _get_json(db, DEFAULT_SOURCES, [])
    if not isinstance(sources, list):
        sources = []

    existing = next(
        (
            s
            for s in sources
            if isinstance(s, dict) and (s.get("id") or s.get("name")) == source_id
        ),
        None,
    )
    created = False
    key = None

    if existing:
        if body.regenerate_key:
            full_key, key_prefix, _ = await regenerate_key(db, source_id)
            key = full_key
        elif body.create_key:
            configured_keys = await list_keys(db)
            has_key = any(info.source_id == source_id for info in configured_keys)
            if not has_key:
                full_key, key_prefix, _ = await create_key(db, source_id)
                key = full_key
    else:
        new_source = {
            "id": source_id,
            "name": name,
            "adapter": "manual",
            "parser": parser,
            "assetType": asset_type,
            "type": "push",
            "color": "#94a3b8",
        }
        sources.append(new_source)
        r = await db.execute(
            select(SettingsKV).where(SettingsKV.key == DEFAULT_SOURCES)
        )
        row = r.scalar_one_or_none()
        if row:
            row.value = sources
            row.updated_at = _utc_now_naive()
        else:
            db.add(
                SettingsKV(
                    key=DEFAULT_SOURCES, value=sources, updated_at=_utc_now_naive()
                )
            )
        await db.commit()
        created = True
        if body.create_key:
            full_key, key_prefix, _ = await create_key(db, source_id)
            key = full_key

    return {
        "sourceId": source_id,
        "created": created,
        "key": key,
    }


@router.put("/sources")
async def put_sources(
    body: list[dict],
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update sources config. Admin only."""
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == DEFAULT_SOURCES))
    row = r.scalar_one_or_none()
    if row:
        row.value = body
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=DEFAULT_SOURCES, value=body, updated_at=_utc_now_naive()))
    await db.commit()
    return {"ok": True}


def _ensure_template_parseable(template: str) -> str:
    """Ensure template has required [VAT] block structure. Appends minimal block if missing."""
    if not template or not isinstance(template, str):
        return DEFAULT_ISSUE_TEMPLATE
    if (
        "status:" in template
        and "justification:" in template
        and "[VAT]" in template
        and "{cve_id}" in template
    ):
        return template
    minimal = "[VAT] {cve_id}\nstatus: false-positive | not-applicable | risk-accepted | mitigated | duplicate\njustification: <required>\ncompensating-controls: <optional>"
    return template.rstrip() + "\n\n" + minimal


@router.put("/tracker")
async def put_tracker(
    body: dict | list,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update tracker config. Admin only. body: single dict or list of trackers."""
    if isinstance(body, list):
        for t in body:
            if isinstance(t, dict) and isinstance(t.get("issueTemplate"), str):
                t["issueTemplate"] = _ensure_template_parseable(t["issueTemplate"])
        r = await db.execute(
            select(SettingsKV).where(SettingsKV.key == DEFAULT_TRACKERS)
        )
        row = r.scalar_one_or_none()
        if row:
            row.value = body
            row.updated_at = _utc_now_naive()
        else:
            db.add(
                SettingsKV(
                    key=DEFAULT_TRACKERS, value=body, updated_at=_utc_now_naive()
                )
            )
        await db.commit()
        return {"ok": True}
    # Single dict: update first tracker or create trackers with single element
    if isinstance(body.get("issueTemplate"), str):
        body = {
            **body,
            "issueTemplate": _ensure_template_parseable(body["issueTemplate"]),
        }
    trackers = await _get_trackers(db)
    if trackers:
        updated = [dict(body) if i == 0 else dict(t) for i, t in enumerate(trackers)]
    else:
        updated = [dict(body)]
    if not any(t.get("id") for t in updated):
        updated[0]["id"] = updated[0].get("id") or "t-default"
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == DEFAULT_TRACKERS))
    row = r.scalar_one_or_none()
    if row:
        row.value = updated
        row.updated_at = _utc_now_naive()
    else:
        db.add(
            SettingsKV(key=DEFAULT_TRACKERS, value=updated, updated_at=_utc_now_naive())
        )
    await db.commit()
    return {"ok": True}


@router.get("/aikido/status")
async def get_aikido_status(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
    source_id: str | None = None,
):
    """Integration status for Aikido (no secrets exposed). Admin only. source_id scopes to per-source credentials."""
    s = get_config()
    base = s.public_url.rstrip("/")
    creds = await get_aikido_credentials(db, source_id)
    client_id = creds.get("client_id") or creds.get("clientId") or s.aikido_client_id
    client_secret = (
        creds.get("client_secret")
        or creds.get("clientSecret")
        or s.aikido_client_secret
    )
    region = creds.get("region") or s.aikido_region or "eu"
    webhook_secret = creds.get("webhook_secret") or s.aikido_webhook_secret
    return {
        "clientIdConfigured": bool(client_id),
        "clientSecretConfigured": bool(client_secret),
        "region": region,
        "oauthConfigured": bool(client_id and client_secret),
        "webhookSecretConfigured": bool(webhook_secret),
        "webhookUrl": f"{base}/webhook/aikido/{source_id}"
        if source_id
        else f"{base}/webhook/aikido",
        "syncBackEnabled": bool(creds.get("sync_back_enabled", True)),
    }


@router.put("/aikido/credentials")
async def put_aikido_credentials(
    body: dict,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update Aikido credentials (stored in DB, overrides env). Admin only. sourceId in body scopes to per-source."""
    source_id = (body.get("sourceId") or body.get("source_id") or "").strip() or None
    if not source_id:
        raise HTTPException(
            status_code=400, detail="sourceId is required for Aikido credentials"
        )
    creds = await _get_credentials(db, _aikido_creds_key(source_id))
    # Normalize to snake_case for storage
    if "clientId" in body:
        creds["client_id"] = (body["clientId"] or "").strip() or None
    if "clientSecret" in body:
        creds["client_secret"] = (body["clientSecret"] or "").strip() or None
    if "region" in body:
        r = (body["region"] or "eu").strip().lower()
        creds["region"] = r if r in ("eu", "us", "me") else "eu"
    if "webhookSecret" in body:
        creds["webhook_secret"] = (body["webhookSecret"] or "").strip() or None
    if "syncBackEnabled" in body:
        creds["sync_back_enabled"] = bool(body["syncBackEnabled"])
    creds.pop("api_key", None)  # Removed: OAuth only
    creds = {k: v for k, v in creds.items() if v is not None}
    key = _aikido_creds_key(source_id)
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == key))
    row = r.scalar_one_or_none()
    if row:
        row.value = creds
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=key, value=creds, updated_at=_utc_now_naive()))
    await db.commit()
    return {"ok": True}


@router.get("/linear/status")
async def get_linear_status(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Integration status for Linear (no secrets exposed). Admin only."""
    s = get_config()
    base = s.public_url.rstrip("/")
    creds = await _get_credentials(db, LINEAR_CREDENTIALS)
    api_key = creds.get("api_key") or s.linear_api_key
    team_id = creds.get("team_id") or s.linear_team_id
    webhook_secret = creds.get("webhook_secret") or s.linear_webhook_secret
    return {
        "apiKeyConfigured": bool(api_key),
        "teamIdConfigured": bool(team_id),
        "webhookSecretConfigured": bool(webhook_secret),
        "webhookUrl": f"{base}/webhook/linear",
        "pollEnabled": s.linear_poll_enabled and not webhook_secret,
        "pollIntervalMin": s.linear_poll_interval_min,
        "pollMaxIssues": s.linear_poll_max_issues,
        "reconcileIntervalHours": s.linear_reconcile_interval_hours,
        "linkTitleFallback": s.linear_link_title_fallback,
        "syncProcessLimit": s.linear_sync_process_limit,
        "syncBackfillLimit": s.linear_sync_backfill_limit,
    }


async def _ensure_linear_labels(db: AsyncSession) -> dict:
    """
    Ensure configured labels exist in Linear (create missing ones).
    Called when Linear integration is saved. Returns {"created": N, "errors": [...]}.
    """
    api_key, team_id, _ = await get_linear_credentials(db)
    if not api_key or not team_id:
        return {"created": 0, "errors": []}
    labels_cfg = await get_labels(db)
    label_names = [l.get("name") for l in labels_cfg if l.get("name")]
    if not label_names:
        label_names = ["security-bug"]
    name_to_color = {
        l.get("name", "").strip().lower(): l.get("color") or "#E53935"
        for l in labels_cfg
        if isinstance(l, dict) and l.get("name")
    }
    if not name_to_color and label_names:
        name_to_color = {n.strip().lower(): "#E53935" for n in label_names}
    try:
        from app.adapters.linear import LinearAdapter

        adapter = LinearAdapter(api_key=api_key, team_id=team_id)
        existing = await adapter._resolve_label_ids(
            label_names, name_to_color=name_to_color
        )
        # _resolve_label_ids creates missing labels; we can't easily count created vs existing
        # Log success; frontend gets ok
        if existing:
            logging.getLogger(__name__).info(
                "Linear labels ensured: %d resolved for team", len(existing)
            )
        return {"created": len(existing), "errors": []}
    except Exception:
        logging.getLogger(__name__).exception("Failed to ensure Linear labels")
        return {"created": 0, "errors": ["linear label sync failed"]}


@router.put("/linear/credentials")
async def put_linear_credentials(
    body: dict,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update Linear API key, team ID, and webhook secret (stored in DB, overrides env). Admin only.
    After save, ensures configured labels exist in Linear (auto-creates missing ones)."""
    creds = await _get_credentials(db, LINEAR_CREDENTIALS)
    if "apiKey" in body:
        creds["api_key"] = (body["apiKey"] or "").strip() or None
    if "teamId" in body:
        creds["team_id"] = (body["teamId"] or "").strip() or None
    if "webhookSecret" in body:
        creds["webhook_secret"] = (body["webhookSecret"] or "").strip() or None
    creds = {k: v for k, v in creds.items() if v is not None}
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == LINEAR_CREDENTIALS))
    row = r.scalar_one_or_none()
    if row:
        row.value = creds
        row.updated_at = _utc_now_naive()
    else:
        db.add(
            SettingsKV(key=LINEAR_CREDENTIALS, value=creds, updated_at=_utc_now_naive())
        )
    if creds.get("api_key") and creds.get("team_id"):
        from app.services.sync_service import reset_failed_tracker_events

        reset_count = await reset_failed_tracker_events(db, "linear")
        if reset_count:
            logging.getLogger(__name__).info(
                "Reset %d failed Linear sync events for retry", reset_count
            )
    await db.commit()
    labels_result = {"created": 0, "errors": []}
    if creds.get("api_key") and creds.get("team_id"):
        labels_result = await _ensure_linear_labels(db)
        from app.tasks.sync_tasks import trigger_sync_worker

        trigger_sync_worker(countdown=2)
    return {"ok": True, "labels": labels_result}


@router.get("/ingest-keys")
async def get_ingest_keys(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """List ingest API key status (no secrets). Admin only."""
    keys = await list_keys(db)
    oauth_clients = await list_oauth_clients(db)
    return {
        "keys": [
            {
                "sourceId": k.source_id,
                "keyPrefix": k.key_prefix,
                "configured": k.configured,
                "authType": k.auth_type,
                "createdAt": k.created_at,
                "rotatedAt": k.rotated_at,
            }
            for k in keys
        ],
        "oauthClients": [
            {
                "sourceId": c.source_id,
                "clientId": c.client_id,
                "createdAt": c.created_at,
                "rotatedAt": c.rotated_at,
            }
            for c in oauth_clients
        ],
    }


class IngestKeyCreateRequest(BaseModel):
    sourceId: str


@router.post("/ingest-keys")
async def post_ingest_key(
    body: IngestKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Generate new API key for sourceId. Key shown once; store securely. Admin only."""
    try:
        full_key, key_prefix, message = await create_key(db, body.sourceId)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "sourceId": body.sourceId,
        "key": full_key,
        "keyPrefix": key_prefix,
        "message": message,
    }


@router.post("/ingest-keys/{source_id}/regenerate")
async def post_ingest_key_regenerate(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Regenerate API key for sourceId. Previous key invalidated. Admin only."""
    full_key, key_prefix, message = await regenerate_key(db, source_id)
    return {
        "sourceId": source_id,
        "key": full_key,
        "keyPrefix": key_prefix,
        "message": message,
    }


@router.delete("/ingest-keys/{source_id}")
async def delete_ingest_key(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Revoke API key for sourceId. Admin only."""
    existed = await revoke_key(db, source_id)
    return {"ok": True, "revoked": existed}


# --- Admin API keys (for automation: scripts, CI, VAT_ADMIN_TOKEN) ---


@router.get("/admin-keys")
async def get_admin_keys(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """List admin API keys (prefix only, no secrets). Admin only."""
    keys = await list_admin_keys(db)
    return {
        "keys": [
            {
                "id": k.id,
                "keyPrefix": k.key_prefix,
                "tenantId": k.tenant_id,
                "crossTenant": k.cross_tenant,
                "legacy": k.legacy,
                "createdAt": k.created_at,
            }
            for k in keys
        ],
    }


class AdminKeyCreateRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None, max_length=64)
    cross_tenant: bool = False


@router.post("/admin-keys")
async def post_admin_key(
    body: AdminKeyCreateRequest | None = None,
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """Create new admin API key. Caller must specify tenant_id OR cross_tenant=True.

    Key shown once; use as VAT_ADMIN_TOKEN. Admin only.
    """
    # Back-compat and UX: allow empty/missing body. Default to a tenant-bound key
    # for the caller's tenant when available; cross-tenant callers with no tenant
    # context default to cross-tenant key creation.
    tenant_id = body.tenant_id if body else None
    cross_tenant = body.cross_tenant if body else False
    if not cross_tenant and not tenant_id:
        if ctx.tenant_id:
            tenant_id = ctx.tenant_id
        elif ctx.cross_tenant:
            cross_tenant = True

    try:
        key_id, full_key, key_prefix, message = await create_admin_key(
            db,
            tenant_id=tenant_id,
            cross_tenant=cross_tenant,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "id": key_id,
        "key": full_key,
        "keyPrefix": key_prefix,
        "tenantId": tenant_id,
        "crossTenant": cross_tenant,
        "message": message,
    }


@router.delete("/admin-keys/{key_id}")
async def delete_admin_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Revoke admin API key. Admin only."""
    existed = await revoke_admin_key(db, key_id)
    return {"ok": True, "revoked": existed}


class OAuthClientCreateRequest(BaseModel):
    sourceId: str


@router.post("/oauth-clients")
async def post_oauth_client(
    body: OAuthClientCreateRequest,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Create OAuth client for sourceId. Returns client_id and client_secret once. Admin only."""
    try:
        client_id, client_secret, message = await create_oauth_client(db, body.sourceId)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "sourceId": body.sourceId,
        "clientId": client_id,
        "clientSecret": client_secret,
        "message": message,
    }


@router.post("/oauth-clients/{source_id}/rotate")
async def post_oauth_client_rotate(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Rotate OAuth client_secret for sourceId. Previous secret invalidated. Admin only."""
    try:
        client_id, client_secret, message = await rotate_oauth_client(db, source_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "sourceId": source_id,
        "clientId": client_id,
        "clientSecret": client_secret,
        "message": message,
    }


@router.delete("/oauth-clients/{source_id}")
async def delete_oauth_client(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Revoke OAuth client for sourceId. Admin only."""
    existed = await revoke_oauth_client(db, source_id)
    return {"ok": True, "revoked": existed}


@router.get("/parsers")
async def get_parsers(_ctx: UserContext = Depends(require_admin)):
    """List available parsers for Manual source config dropdown. Admin only."""
    from app.parsers import list_parsers

    return {"parsers": list_parsers()}


@router.get("/trivy/status")
async def get_trivy_status(
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Integration status for Trivy/push sources (no secrets exposed). Admin only."""
    s = get_config()
    base = s.public_url.rstrip("/")
    keys = await list_keys(db)
    trivy_keys = [
        k for k in keys if k.source_id.startswith("trivy") or k.source_id == "trivy-ci"
    ]
    return {
        "ingestUrl": f"{base}/api/ingest",
        "ingestUrlJson": f"{base}/api/ingest",
        "apiKeyConfigured": bool(trivy_keys) or bool(s.ingest_api_key),
        "keys": [
            {"sourceId": k.source_id, "keyPrefix": k.key_prefix} for k in trivy_keys
        ],
    }


@router.get("/vat/status")
async def get_vat_status(_ctx: UserContext = Depends(require_admin)):
    """VAT backend status (no secrets exposed). Admin only."""
    s = get_config()
    base = s.public_url.rstrip("/")
    return {
        "databaseConfigured": bool(s.database_url),
        "secretKeyConfigured": bool(
            s.secret_key and s.secret_key != "change-me-in-production"
        ),
        "publicUrl": base,
        "aikidoWebhookUrl": f"{base}/webhook/aikido",
        "linearWebhookUrl": f"{base}/webhook/linear",
        "ingestUrl": f"{base}/api/ingest",
        "ingestSarifUrl": f"{base}/api/ingest",
    }


@router.put("/labels")
async def put_labels(
    body: list[dict],
    db: AsyncSession = Depends(get_db),
    _ctx: UserContext = Depends(require_admin),
):
    """Update labels applied when creating Linear issues. Admin only."""
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == DEFAULT_LABELS))
    row = r.scalar_one_or_none()
    if row:
        row.value = body
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=DEFAULT_LABELS, value=body, updated_at=_utc_now_naive()))
    await db.commit()
    return {"ok": True}
