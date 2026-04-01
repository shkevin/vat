"""Keyless public vulnerability feed ingestion services."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

import httpx
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.sbom import SbomPackage
from app.models.vuln_feed_record import VulnFeedRecord
from app.models.vuln_feed_run import VulnFeedRun
from app.models.vuln_feed_source import VulnFeedSource
from app.services.audit_events import emit_audit_event, new_trace_id

SOURCE_OSV = "osv"
SOURCE_CISA_KEV = "cisa_kev"
SOURCE_REDHAT = "redhat"
SOURCE_DEBIAN = "debian"
SOURCE_UBUNTU = "ubuntu"
SOURCE_ALPINE = "alpine"
SOURCE_ALMALINUX = "almalinux"

ALL_SOURCES = (
    SOURCE_OSV,
    SOURCE_CISA_KEV,
    SOURCE_REDHAT,
    SOURCE_DEBIAN,
    SOURCE_UBUNTU,
    SOURCE_ALPINE,
    SOURCE_ALMALINUX,
)

_ECOSYSTEM_BY_LANGUAGE = {
    "python": "PyPI",
    "javascript": "npm",
    "typescript": "npm",
    "node": "npm",
    "go": "Go",
    "golang": "Go",
    "java": "Maven",
    "ruby": "RubyGems",
    "rust": "crates.io",
    "alpine": "Alpine",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
}


@dataclass
class IngestionStats:
    source: str
    fetched_items: int
    inserted: int
    updated: int
    failed: bool = False
    error: str | None = None
    checksum: str | None = None
    etag: str | None = None


def _utc_now() -> datetime:
    return datetime.utcnow()


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _checksum_for_payload(value: Any) -> str:
    return hashlib.sha256(_compact_json(value).encode("utf-8")).hexdigest()


def _to_dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v).replace(tzinfo=None)
    except Exception:
        return None


def _record_key(parts: Iterable[str | None]) -> str:
    normalized = [p.strip() for p in parts if p and p.strip()]
    return "|".join(normalized)[:256]


def _severity_from_osv(v: dict[str, Any]) -> str | None:
    severity = v.get("severity")
    if isinstance(severity, list) and severity:
        first = severity[0] or {}
        if isinstance(first, dict):
            score = first.get("score")
            if isinstance(score, str) and score:
                return score[:32]
    dbs = v.get("database_specific")
    if isinstance(dbs, dict):
        sev = dbs.get("severity")
        if isinstance(sev, str):
            return sev[:32]
    return None


def _normalize_osv_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for result in results:
        package = (result or {}).get("package") or {}
        package_name = package.get("name")
        ecosystem = package.get("ecosystem")
        version = (result or {}).get("version")
        for vuln in (result or {}).get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            aliases = [
                a for a in (vuln.get("aliases") or []) if isinstance(a, str) and a.strip()
            ]
            published = _to_dt(vuln.get("published"))
            modified = _to_dt(vuln.get("modified"))
            record_key = _record_key(
                [vuln_id or "", package_name or "", ecosystem or "", version or ""]
            )
            if not record_key:
                continue
            normalized.append(
                {
                    "source": SOURCE_OSV,
                    "record_key": record_key,
                    "vulnerability_id": vuln_id[:128] if isinstance(vuln_id, str) else None,
                    "aliases": aliases,
                    "package_name": package_name[:256] if isinstance(package_name, str) else None,
                    "ecosystem": ecosystem[:64] if isinstance(ecosystem, str) else None,
                    "version": version[:128] if isinstance(version, str) else None,
                    "severity": _severity_from_osv(vuln),
                    "title": (
                        vuln.get("summary")[:4000]
                        if isinstance(vuln.get("summary"), str)
                        else None
                    ),
                    "details": vuln,
                    "published_at": published,
                    "modified_at": modified,
                }
            )
    return normalized


def _normalize_cisa_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = item.get("cveID")
        if not isinstance(cve, str) or not cve.strip():
            continue
        record_key = _record_key([cve])
        normalized.append(
            {
                "source": SOURCE_CISA_KEV,
                "record_key": record_key,
                "vulnerability_id": cve[:128],
                "aliases": [cve],
                "package_name": item.get("vendorProject"),
                "ecosystem": None,
                "version": None,
                "severity": item.get("knownRansomwareCampaignUse"),
                "title": item.get("vulnerabilityName"),
                "details": item,
                "published_at": _to_dt(item.get("dateAdded")),
                "modified_at": _to_dt(payload.get("dateReleased")),
            }
        )
    return normalized


def _normalize_redhat(cve_ids: list[str]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for cve in cve_ids:
        record_key = _record_key([cve])
        normalized.append(
            {
                "source": SOURCE_REDHAT,
                "record_key": record_key,
                "vulnerability_id": cve[:128],
                "aliases": [cve],
                "package_name": None,
                "ecosystem": "rpm",
                "version": None,
                "severity": None,
                "title": None,
                "details": {"cve": cve},
                "published_at": None,
                "modified_at": None,
            }
        )
    return normalized


def _normalize_debian(payload: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    count = 0
    for cve_id, packages in payload.items():
        if count >= limit:
            break
        if not isinstance(cve_id, str):
            continue
        details = packages if isinstance(packages, dict) else {}
        out.append(
            {
                "source": SOURCE_DEBIAN,
                "record_key": _record_key([cve_id]),
                "vulnerability_id": cve_id[:128],
                "aliases": [cve_id],
                "package_name": None,
                "ecosystem": "Debian",
                "version": None,
                "severity": None,
                "title": None,
                "details": details,
                "published_at": None,
                "modified_at": None,
            }
        )
        count += 1
    return out


def _normalize_ubuntu(payload: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]]
    raw = payload.get("cves")
    if isinstance(raw, list):
        entries = [x for x in raw if isinstance(x, dict)]
    elif isinstance(payload, list):
        entries = [x for x in payload if isinstance(x, dict)]  # type: ignore[arg-type]
    else:
        entries = []
    out: list[dict[str, Any]] = []
    for row in entries[:limit]:
        cve = row.get("id") or row.get("cve") or row.get("name")
        if not isinstance(cve, str) or not cve.strip():
            continue
        out.append(
            {
                "source": SOURCE_UBUNTU,
                "record_key": _record_key([cve]),
                "vulnerability_id": cve[:128],
                "aliases": [cve],
                "package_name": row.get("package"),
                "ecosystem": "Ubuntu",
                "version": row.get("priority"),
                "severity": row.get("priority"),
                "title": row.get("description"),
                "details": row,
                "published_at": _to_dt(row.get("published")),
                "modified_at": _to_dt(row.get("updated_at") or row.get("modified")),
            }
        )
    return out


def _extract_alpine_json_links(html: str) -> list[str]:
    links = re.findall(r'href="([^"]+\.json)"', html)
    seen: set[str] = set()
    out: list[str] = []
    for href in links:
        candidate = href.strip()
        if not candidate:
            continue
        if candidate.startswith("http"):
            url = candidate
        else:
            url = f"https://secdb.alpinelinux.org/{candidate.lstrip('/')}"
        if "/v" not in url:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def _normalize_alpine(docs: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for doc in docs:
        package_data = doc.get("packages")
        if not isinstance(package_data, dict):
            continue
        for package_name, pkg_details in package_data.items():
            if len(out) >= limit:
                return out
            if not isinstance(pkg_details, dict):
                continue
            secfixes = pkg_details.get("secfixes")
            if not isinstance(secfixes, dict):
                continue
            for version, cves in secfixes.items():
                if not isinstance(cves, list):
                    continue
                for cve in cves:
                    if len(out) >= limit:
                        return out
                    if not isinstance(cve, str) or not cve.strip():
                        continue
                    out.append(
                        {
                            "source": SOURCE_ALPINE,
                            "record_key": _record_key([cve, package_name, version]),
                            "vulnerability_id": cve[:128],
                            "aliases": [cve],
                            "package_name": package_name[:256],
                            "ecosystem": "Alpine",
                            "version": version[:128] if isinstance(version, str) else None,
                            "severity": None,
                            "title": None,
                            "details": {
                                "package": package_name,
                                "version": version,
                                "release": doc.get("distroversion"),
                            },
                            "published_at": None,
                            "modified_at": None,
                        }
                    )
    return out


def _normalize_almalinux(html: str, limit: int) -> list[dict[str, Any]]:
    ids = re.findall(r"ALSA-\d{4}:\d+", html)
    out: list[dict[str, Any]] = []
    for advisory in ids[:limit]:
        out.append(
            {
                "source": SOURCE_ALMALINUX,
                "record_key": _record_key([advisory]),
                "vulnerability_id": advisory[:128],
                "aliases": [advisory],
                "package_name": None,
                "ecosystem": "AlmaLinux",
                "version": None,
                "severity": None,
                "title": "AlmaLinux advisory",
                "details": {"advisory": advisory},
                "published_at": None,
                "modified_at": None,
            }
        )
    return out


async def _upsert_source_state(
    db: AsyncSession,
    *,
    source: str,
    status: str,
    item_count: int,
    checksum: str | None,
    etag: str | None,
    error: str | None,
) -> None:
    now = _utc_now()
    row = await db.scalar(
        select(VulnFeedSource).where(VulnFeedSource.source == source).limit(1)
    )
    if not row:
        row = VulnFeedSource(source=source)
        db.add(row)
    row.last_status = status
    row.last_attempt_at = now
    row.last_item_count = item_count
    row.last_checksum = checksum
    row.last_etag = etag
    row.last_error = error
    row.updated_at = now
    if status == "completed":
        row.last_success_at = now


async def _upsert_records(
    db: AsyncSession,
    *,
    source: str,
    run_id: str,
    records: list[dict[str, Any]],
) -> tuple[int, int]:
    inserted = 0
    updated = 0
    now = _utc_now()
    keys = [r["record_key"] for r in records if r.get("record_key")]
    existing_rows: dict[str, VulnFeedRecord] = {}
    if keys:
        rows = (
            (
                await db.execute(
                    select(VulnFeedRecord).where(
                        VulnFeedRecord.source == source,
                        VulnFeedRecord.record_key.in_(keys),
                    )
                )
            )
            .scalars()
            .all()
        )
        existing_rows = {r.record_key: r for r in rows}

    for rec in records:
        key = rec.get("record_key")
        if not isinstance(key, str) or not key:
            continue
        row = existing_rows.get(key)
        if not row:
            row = VulnFeedRecord(source=source, record_key=key)
            db.add(row)
            inserted += 1
        else:
            updated += 1
        row.vulnerability_id = rec.get("vulnerability_id")
        row.aliases = rec.get("aliases") or []
        row.package_name = rec.get("package_name")
        row.ecosystem = rec.get("ecosystem")
        row.version = rec.get("version")
        row.severity = rec.get("severity")
        row.title = rec.get("title")
        row.details = rec.get("details") or {}
        row.published_at = rec.get("published_at")
        row.modified_at = rec.get("modified_at")
        row.fetched_at = now
        row.run_id = run_id
    return inserted, updated


async def _fetch_osv_records(client: httpx.AsyncClient, db: AsyncSession) -> tuple[list[dict[str, Any]], str]:
    settings = get_settings()
    max_queries = max(0, settings.vuln_feed_osv_max_queries)
    if max_queries == 0:
        return [], _checksum_for_payload([])

    sbom_rows = (
        (
            await db.execute(
                select(SbomPackage.name, SbomPackage.version, SbomPackage.language).limit(
                    max_queries
                )
            )
        )
        .all()
    )
    queries = []
    for name, version, language in sbom_rows:
        if not name or not version:
            continue
        ecosystem = _ECOSYSTEM_BY_LANGUAGE.get((language or "").lower())
        if not ecosystem:
            continue
        queries.append(
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version,
            }
        )
    if not queries:
        return [], _checksum_for_payload([])

    resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
    resp.raise_for_status()
    payload = resp.json()
    results = payload.get("results") if isinstance(payload, dict) else []
    normalized_input: list[dict[str, Any]] = []
    if isinstance(results, list):
        for idx, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            entry = {"package": queries[idx]["package"], "version": queries[idx]["version"], **result}
            normalized_input.append(entry)
    normalized = _normalize_osv_results(normalized_input)
    return normalized, _checksum_for_payload(payload)


async def _fetch_cisa_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str, str | None]:
    resp = await client.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    resp.raise_for_status()
    payload = resp.json()
    etag = resp.headers.get("etag")
    return _normalize_cisa_kev(payload if isinstance(payload, dict) else {}), _checksum_for_payload(payload), etag


async def _fetch_redhat_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    # Red Hat moved security data endpoints from /labs/... to /hydra/rest/securitydata.
    # Some environments return 403 for bare /cve.json but allow the same endpoint with query params.
    errors: list[str] = []
    payload: Any = []
    for url in (
        "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=1000",
        "https://access.redhat.com/hydra/rest/securitydata/cve.json?after=1970-01-01",
        "https://access.redhat.com/hydra/rest/securitydata/cve.json",
        "https://access.redhat.com/labs/securitydataapi/cve.json",
    ):
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            payload = resp.json()
            break
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            continue
    if not payload:
        raise RuntimeError(
            "All Red Hat CVE endpoints failed. " + " | ".join(errors[:4])
        )
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    ids: list[str] = []
    if isinstance(payload, list):
        for item in payload[:max_items]:
            if isinstance(item, str) and item.strip():
                ids.append(item.strip())
            elif isinstance(item, dict):
                cve = item.get("CVE") or item.get("name") or item.get("id")
                if isinstance(cve, str) and cve.strip():
                    ids.append(cve.strip())
    return _normalize_redhat(ids), _checksum_for_payload(payload)


async def _fetch_debian_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    resp = await client.get("https://security-tracker.debian.org/tracker/data/json")
    resp.raise_for_status()
    payload = resp.json()
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    normalized = _normalize_debian(payload if isinstance(payload, dict) else {}, max_items)
    return normalized, _checksum_for_payload(payload)


async def _fetch_ubuntu_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    resp = await client.get("https://ubuntu.com/security/cves.json")
    resp.raise_for_status()
    payload = resp.json()
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    normalized = _normalize_ubuntu(payload if isinstance(payload, dict) else {}, max_items)
    return normalized, _checksum_for_payload(payload)


async def _fetch_alpine_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    index_resp = await client.get("https://secdb.alpinelinux.org/")
    index_resp.raise_for_status()
    links = _extract_alpine_json_links(index_resp.text)
    docs: list[dict[str, Any]] = []
    for url in links[:10]:
        try:
            res = await client.get(url)
            if not res.is_success:
                continue
            payload = res.json()
            if isinstance(payload, dict):
                docs.append(payload)
        except Exception:
            continue
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    normalized = _normalize_alpine(docs, max_items)
    return normalized, _checksum_for_payload({"links": links, "docs": len(docs)})


async def _fetch_almalinux_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    resp = await client.get("https://errata.almalinux.org/")
    resp.raise_for_status()
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    normalized = _normalize_almalinux(resp.text, max_items)
    return normalized, _checksum_for_payload({"html_len": len(resp.text), "items": len(normalized)})


async def refresh_source(
    db: AsyncSession,
    *,
    source: str,
    trace_id: str,
    actor_id: str = "system",
) -> IngestionStats:
    settings = get_settings()
    run_id = uuid.uuid4().hex
    run = VulnFeedRun(
        id=run_id,
        source=source,
        status="running",
        trace_id=trace_id,
        stats={},
        started_at=_utc_now(),
    )
    db.add(run)
    await db.flush()

    timeout = httpx.Timeout(settings.vuln_feed_request_timeout_sec)
    headers = {"User-Agent": settings.vuln_feed_user_agent}
    records: list[dict[str, Any]] = []
    checksum: str | None = None
    etag: str | None = None

    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            if source == SOURCE_OSV:
                records, checksum = await _fetch_osv_records(client, db)
            elif source == SOURCE_CISA_KEV:
                records, checksum, etag = await _fetch_cisa_records(client)
            elif source == SOURCE_REDHAT:
                records, checksum = await _fetch_redhat_records(client)
            elif source == SOURCE_DEBIAN:
                records, checksum = await _fetch_debian_records(client)
            elif source == SOURCE_UBUNTU:
                records, checksum = await _fetch_ubuntu_records(client)
            elif source == SOURCE_ALPINE:
                records, checksum = await _fetch_alpine_records(client)
            elif source == SOURCE_ALMALINUX:
                records, checksum = await _fetch_almalinux_records(client)
            else:
                raise ValueError(f"Unsupported feed source: {source}")

        inserted, updated = await _upsert_records(
            db, source=source, run_id=run_id, records=records
        )
        run.status = "completed"
        run.stats = {
            "fetched_items": len(records),
            "inserted": inserted,
            "updated": updated,
        }
        run.completed_at = _utc_now()
        await _upsert_source_state(
            db,
            source=source,
            status="completed",
            item_count=len(records),
            checksum=checksum,
            etag=etag,
            error=None,
        )
        await emit_audit_event(
            db,
            trace_id=trace_id,
            event_type="vuln_feed.refresh.completed",
            actor_type="user" if actor_id != "system" else "system",
            actor_id=actor_id,
            source_id=source,
            decision_name="vuln_feed_refresh",
            decision_reason_code="scheduled_or_manual",
            decision_confidence="high",
            decision_result="completed",
            data=run.stats,
        )
        return IngestionStats(
            source=source,
            fetched_items=len(records),
            inserted=inserted,
            updated=updated,
            failed=False,
            checksum=checksum,
            etag=etag,
        )
    except Exception as exc:
        err = str(exc)
        run.status = "failed"
        run.error = err[:4000]
        run.completed_at = _utc_now()
        run.stats = {"fetched_items": len(records), "inserted": 0, "updated": 0}
        await _upsert_source_state(
            db,
            source=source,
            status="failed",
            item_count=0,
            checksum=checksum,
            etag=etag,
            error=err,
        )
        await emit_audit_event(
            db,
            trace_id=trace_id,
            event_type="vuln_feed.refresh.failed",
            actor_type="user" if actor_id != "system" else "system",
            actor_id=actor_id,
            source_id=source,
            decision_name="vuln_feed_refresh",
            decision_reason_code="source_fetch_error",
            decision_confidence="high",
            decision_result="failed",
            data={"error": err[:2000]},
        )
        return IngestionStats(
            source=source,
            fetched_items=len(records),
            inserted=0,
            updated=0,
            failed=True,
            error=err,
            checksum=checksum,
            etag=etag,
        )


def _enabled_sources() -> list[str]:
    settings = get_settings()
    sources: list[str] = []
    if settings.vuln_feed_osv_enabled:
        sources.append(SOURCE_OSV)
    if settings.vuln_feed_cisa_enabled:
        sources.append(SOURCE_CISA_KEV)
    if settings.vuln_feed_redhat_enabled:
        sources.append(SOURCE_REDHAT)
    if settings.vuln_feed_debian_enabled:
        sources.append(SOURCE_DEBIAN)
    if settings.vuln_feed_ubuntu_enabled:
        sources.append(SOURCE_UBUNTU)
    if settings.vuln_feed_alpine_enabled:
        sources.append(SOURCE_ALPINE)
    if settings.vuln_feed_almalinux_enabled:
        sources.append(SOURCE_ALMALINUX)
    return sources


async def refresh_enabled_feeds(
    db: AsyncSession,
    *,
    trace_id: str | None = None,
    actor_id: str = "system",
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.vuln_feeds_enabled:
        return {"enabled": False, "sources": [], "stats": []}
    run_trace_id = trace_id or new_trace_id()
    stats: list[dict[str, Any]] = []
    for source in _enabled_sources():
        source_stats = await refresh_source(
            db, source=source, trace_id=run_trace_id, actor_id=actor_id
        )
        stats.append(
            {
                "source": source_stats.source,
                "fetched_items": source_stats.fetched_items,
                "inserted": source_stats.inserted,
                "updated": source_stats.updated,
                "failed": source_stats.failed,
                "error": source_stats.error,
                "checksum": source_stats.checksum,
                "etag": source_stats.etag,
            }
        )
    return {"enabled": True, "sources": _enabled_sources(), "stats": stats}


async def get_feed_summary(db: AsyncSession) -> dict[str, Any]:
    states = (
        (await db.execute(select(VulnFeedSource).order_by(VulnFeedSource.source.asc())))
        .scalars()
        .all()
    )
    rows = (
        (
            await db.execute(
                select(
                    VulnFeedRecord.source,
                    func.count(VulnFeedRecord.id),
                    func.max(VulnFeedRecord.fetched_at),
                ).group_by(VulnFeedRecord.source)
            )
        )
        .all()
    )
    count_by_source = {r[0]: int(r[1] or 0) for r in rows}
    last_record_by_source = {r[0]: r[2] for r in rows}

    severity_rows = (
        (
            await db.execute(
                select(VulnFeedRecord.severity, func.count(VulnFeedRecord.id)).group_by(
                    VulnFeedRecord.severity
                )
            )
        )
        .all()
    )
    severity_breakdown = {
        (sev or "unknown"): int(count or 0) for sev, count in severity_rows
    }

    source_map = {s.source: s for s in states}
    for source in ALL_SOURCES:
        if source not in source_map:
            source_map[source] = VulnFeedSource(source=source, last_status="never")

    sources = []
    for source in sorted(source_map.keys()):
        state = source_map[source]
        sources.append(
            {
                "source": source,
                "last_status": state.last_status,
                "last_attempt_at": (
                    state.last_attempt_at.isoformat() if state.last_attempt_at else None
                ),
                "last_success_at": (
                    state.last_success_at.isoformat() if state.last_success_at else None
                ),
                "last_error": state.last_error,
                "last_item_count": state.last_item_count,
                "last_checksum": state.last_checksum,
                "record_count": count_by_source.get(source, 0),
                "last_record_at": (
                    last_record_by_source.get(source).isoformat()
                    if last_record_by_source.get(source)
                    else None
                ),
            }
        )
    total_records = sum(count_by_source.values())
    return {
        "total_records": total_records,
        "severity_breakdown": severity_breakdown,
        "sources": sources,
    }


async def get_feed_runs(
    db: AsyncSession,
    *,
    source: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    q = select(VulnFeedRun).order_by(desc(VulnFeedRun.started_at)).limit(limit)
    if source:
        q = q.where(VulnFeedRun.source == source)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": r.id,
            "source": r.source,
            "status": r.status,
            "trace_id": r.trace_id,
            "stats": r.stats or {},
            "error": r.error,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in rows
    ]


async def match_sbom_with_osv(
    db: AsyncSession, *, package_limit: int = 250
) -> dict[str, Any]:
    settings = get_settings()
    timeout = httpx.Timeout(settings.vuln_feed_request_timeout_sec)
    headers = {"User-Agent": settings.vuln_feed_user_agent}

    sbom_rows = (
        (
            await db.execute(
                select(SbomPackage.name, SbomPackage.version, SbomPackage.language).limit(
                    max(1, package_limit)
                )
            )
        )
        .all()
    )

    queries = []
    for name, version, language in sbom_rows:
        if not name or not version:
            continue
        ecosystem = _ECOSYSTEM_BY_LANGUAGE.get((language or "").lower())
        if not ecosystem:
            continue
        queries.append({"package": {"name": name, "ecosystem": ecosystem}, "version": version})
    if not queries:
        return {"query_count": 0, "vuln_count": 0, "results": []}

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
        resp.raise_for_status()
        payload = resp.json()

    output: list[dict[str, Any]] = []
    results = payload.get("results") if isinstance(payload, dict) else []
    if isinstance(results, list):
        for idx, row in enumerate(results):
            if not isinstance(row, dict):
                continue
            vulns = row.get("vulns")
            if not isinstance(vulns, list) or not vulns:
                continue
            pkg = queries[idx]["package"]
            output.append(
                {
                    "package": pkg["name"],
                    "ecosystem": pkg["ecosystem"],
                    "version": queries[idx]["version"],
                    "vulns": [
                        {
                            "id": v.get("id"),
                            "aliases": v.get("aliases") or [],
                            "summary": v.get("summary"),
                        }
                        for v in vulns
                        if isinstance(v, dict)
                    ],
                }
            )
    vuln_count = sum(len(x.get("vulns", [])) for x in output)
    return {"query_count": len(queries), "vuln_count": vuln_count, "results": output}


async def top_vulnerabilities(
    db: AsyncSession, *, limit: int = 25
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(VulnFeedRecord.vulnerability_id, func.count(VulnFeedRecord.id))
                .where(VulnFeedRecord.vulnerability_id.is_not(None))
                .group_by(VulnFeedRecord.vulnerability_id)
                .order_by(func.count(VulnFeedRecord.id).desc())
                .limit(limit)
            )
        )
        .all()
    )
    return [{"vulnerability_id": row[0], "count": int(row[1] or 0)} for row in rows]


async def get_feed_records(
    db: AsyncSession,
    *,
    source: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    q = select(VulnFeedRecord)
    count_q = select(func.count(VulnFeedRecord.id))

    clauses = []
    if source:
        clauses.append(VulnFeedRecord.source == source)
    if severity:
        clauses.append(VulnFeedRecord.severity == severity)
    if search:
        term = f"%{search.strip()}%"
        clauses.append(
            or_(
                VulnFeedRecord.vulnerability_id.ilike(term),
                VulnFeedRecord.package_name.ilike(term),
                VulnFeedRecord.title.ilike(term),
                VulnFeedRecord.record_key.ilike(term),
            )
        )
    for clause in clauses:
        q = q.where(clause)
        count_q = count_q.where(clause)

    total = int((await db.execute(count_q)).scalar() or 0)
    rows = (
        (
            await db.execute(
                q.order_by(desc(VulnFeedRecord.fetched_at))
                .offset(max(0, offset))
                .limit(max(1, min(200, limit)))
            )
        )
        .scalars()
        .all()
    )
    records = [
        {
            "id": row.id,
            "source": row.source,
            "record_key": row.record_key,
            "vulnerability_id": row.vulnerability_id,
            "aliases": row.aliases or [],
            "package_name": row.package_name,
            "ecosystem": row.ecosystem,
            "version": row.version,
            "severity": row.severity,
            "title": row.title,
            "details": row.details or {},
            "published_at": row.published_at.isoformat() if row.published_at else None,
            "modified_at": row.modified_at.isoformat() if row.modified_at else None,
            "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
            "run_id": row.run_id,
        }
        for row in rows
    ]
    return {"total": total, "count": len(records), "records": records}
