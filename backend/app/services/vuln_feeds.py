"""Keyless public vulnerability feed ingestion services."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, BinaryIO, Iterable
from urllib.parse import unquote

import httpx
import ijson
from sqlalchemy import delete, desc, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.asset import Asset
from app.models.asset_alias import AssetAlias
from app.models.finding import Finding, FindingType, Severity, Status
from app.models.settings_model import SettingsKV
from app.models.sbom import SbomPackage
from app.models.vuln_feed_record import VulnFeedRecord
from app.models.vuln_feed_run import VulnFeedRun
from app.models.vuln_feed_source import VulnFeedSource
from app.services.asset_resolver import infer_asset_kind
from app.services.audit_events import emit_audit_event, new_trace_id
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)
from app.services.dedup import make_fingerprint

SOURCE_OSV = "osv"
SOURCE_CISA_KEV = "cisa_kev"
SOURCE_REDHAT = "redhat"
SOURCE_DEBIAN = "debian"
SOURCE_UBUNTU = "ubuntu"
SOURCE_ALPINE = "alpine"
SOURCE_ALMALINUX = "almalinux"
VULN_FEED_REFRESH_STATUS_KEY = "vuln_feed_refresh_status"
VULN_FEED_REFRESH_LOCK_ID = 903412260501

ALL_SOURCES = (
    SOURCE_OSV,
    SOURCE_CISA_KEV,
    SOURCE_REDHAT,
    SOURCE_DEBIAN,
    SOURCE_UBUNTU,
    SOURCE_ALPINE,
    SOURCE_ALMALINUX,
)
SOURCE_VULN_FEED_MATCH = "vuln_feed_match"

_ECOSYSTEM_BY_LANGUAGE = {
    "python": "PyPI",
    "pypi": "PyPI",
    "javascript": "npm",
    "npm": "npm",
    "nodejs": "npm",
    "node.js": "npm",
    "typescript": "npm",
    "node": "npm",
    "go": "Go",
    "golang": "Go",
    "gomod": "Go",
    "go-module": "Go",
    "go mod": "Go",
    "java": "Maven",
    "maven": "Maven",
    "ruby": "RubyGems",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "rust": "crates.io",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "nuget": "NuGet",
    "alpine": "Alpine",
    "apk": "Alpine",
    "debian": "Debian",
    "deb": "Debian",
    "ubuntu": "Ubuntu",
}

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "important": "HIGH",  # Red Hat label between medium/high
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "negligible": "LOW",
    "unimportant": "LOW",
    "unknown": "UNKNOWN",
    "not yet assigned": "UNKNOWN",
    "undetermined": "UNKNOWN",
}


@dataclass
class IngestionStats:
    source: str
    fetched_items: int
    inserted: int
    updated: int
    raw_fetched_items: int = 0
    filtered_by_age: int = 0
    filtered_by_cap: int = 0
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


def _checksum_for_feed_records(records: list[dict[str, Any]]) -> str:
    return _checksum_for_payload(records)


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


def _now_iso() -> str:
    return _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _active_feed_refresh_status(
    value: dict[str, Any] | None,
    *,
    updated_at: datetime | None,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("status") not in {"queued", "running"}:
        return None
    settings = get_settings()
    stale_after = max(60, int(settings.vuln_feed_refresh_stale_after_seconds or 0))
    if updated_at is None or _utc_now() - updated_at <= timedelta(seconds=stale_after):
        return value
    return None


async def read_vuln_feed_refresh_status(db: AsyncSession) -> dict[str, Any] | None:
    row = await db.scalar(
        select(SettingsKV)
        .where(SettingsKV.key == VULN_FEED_REFRESH_STATUS_KEY)
        .limit(1)
    )
    if not row:
        return None
    return _active_feed_refresh_status(row.value, updated_at=row.updated_at)


async def _write_vuln_feed_refresh_status(
    db: AsyncSession,
    *,
    status: str,
    actor_id: str,
    task_id: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    value: dict[str, Any] = {
        "status": status,
        "actor_id": actor_id,
        "task_id": task_id,
        "message": message,
        "updated_at": _now_iso(),
    }
    row = await db.scalar(
        select(SettingsKV)
        .where(SettingsKV.key == VULN_FEED_REFRESH_STATUS_KEY)
        .limit(1)
    )
    if not row:
        row = SettingsKV(key=VULN_FEED_REFRESH_STATUS_KEY, value=value, updated_at=now)
        db.add(row)
    else:
        row.value = value
        row.updated_at = now
    await db.flush()
    return value


async def request_vuln_feed_refresh_enqueue(
    db: AsyncSession,
    *,
    actor_id: str,
) -> tuple[bool, dict[str, Any]]:
    row = await db.scalar(
        select(SettingsKV)
        .where(SettingsKV.key == VULN_FEED_REFRESH_STATUS_KEY)
        .limit(1)
    )
    active = _active_feed_refresh_status(
        row.value if row else None,
        updated_at=row.updated_at if row else None,
    )
    if active:
        return False, active
    return True, await _write_vuln_feed_refresh_status(
        db,
        status="queued",
        actor_id=actor_id,
        message="Vulnerability feed refresh queued.",
    )


async def mark_vuln_feed_refresh_running(
    db: AsyncSession,
    *,
    actor_id: str,
    task_id: str | None = None,
) -> dict[str, Any]:
    return await _write_vuln_feed_refresh_status(
        db,
        status="running",
        actor_id=actor_id,
        task_id=task_id,
        message="Vulnerability feed refresh running.",
    )


async def mark_vuln_feed_refresh_finished(
    db: AsyncSession,
    *,
    status: str,
    actor_id: str,
    task_id: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    return await _write_vuln_feed_refresh_status(
        db,
        status=status,
        actor_id=actor_id,
        task_id=task_id,
        message=message,
    )


async def try_acquire_vuln_feed_refresh_lock(db: AsyncSession) -> bool:
    return bool(
        (
            await db.execute(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": VULN_FEED_REFRESH_LOCK_ID},
            )
        ).scalar_one()
    )


async def release_vuln_feed_refresh_lock(db: AsyncSession) -> None:
    with contextlib.suppress(Exception):
        await db.execute(
            text("SELECT pg_advisory_unlock(:lock_id)"),
            {"lock_id": VULN_FEED_REFRESH_LOCK_ID},
        )


def _infer_ecosystem_for_sbom(
    *,
    name: str | None,
    version: str | None,
    language: str | None,
) -> str | None:
    lang_key = (language or "").strip().lower()
    if lang_key:
        mapped = _ECOSYSTEM_BY_LANGUAGE.get(lang_key)
        if mapped:
            return mapped

    pkg = (name or "").strip().lower()
    ver = (version or "").strip().lower()
    if not pkg:
        return None

    # Go modules commonly appear as full module paths.
    if pkg.startswith(("github.com/", "golang.org/", "gopkg.in/")):
        return "Go"
    # Alpine/apk version suffix pattern, e.g. 20251003-r4.
    if re.search(r"-r\d+$", ver):
        return "Alpine"
    # Maven coordinates often encoded as group:artifact.
    if ":" in pkg and "." in pkg.split(":", 1)[0]:
        return "Maven"
    # npm scoped package form.
    if pkg.startswith("@"):
        return "npm"
    return None


def _parse_purl(value: str | None) -> tuple[str, str, str | None] | None:
    raw = (value or "").strip()
    if not raw or not raw.startswith("pkg:"):
        return None
    body = raw[4:]
    if "#" in body:
        body = body.split("#", 1)[0]
    if "?" in body:
        body = body.split("?", 1)[0]
    if not body or "/" not in body:
        return None
    purl_type, remainder = body.split("/", 1)
    purl_type = unquote((purl_type or "").strip().lower())
    if not purl_type:
        return None
    version: str | None = None
    if "@" in remainder:
        remainder, version = remainder.rsplit("@", 1)
    path = unquote((remainder or "").strip())
    version = unquote((version or "").strip()) or None
    if not path:
        return None
    return purl_type, path, version


def _purl_to_osv_target(
    *, purl: str | None, fallback_name: str | None
) -> tuple[str, str] | None:
    parsed = _parse_purl(purl)
    if not parsed:
        return None
    purl_type, path, _version = parsed

    ecosystem_by_type = {
        "pypi": "PyPI",
        "npm": "npm",
        "golang": "Go",
        "go": "Go",
        "maven": "Maven",
        "gem": "RubyGems",
        "cargo": "crates.io",
        "nuget": "NuGet",
        "apk": "Alpine",
        "deb": "Debian",
    }
    ecosystem = ecosystem_by_type.get(purl_type)
    if not ecosystem:
        return None

    pkg_name = path
    # purl names are namespace/name for some ecosystems; OSV expects ecosystem-specific names.
    if purl_type in {"pypi", "nuget", "gem", "cargo", "apk", "deb"}:
        pkg_name = path.split("/")[-1]
    elif purl_type == "maven":
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            pkg_name = f"{parts[0]}:{parts[1]}"
    # npm scoped packages remain @scope/name.
    if purl_type == "npm":
        pkg_name = path
    # Go module keeps full module path.
    if purl_type in {"golang", "go"}:
        pkg_name = path

    pkg_name = (pkg_name or "").strip()
    if not pkg_name:
        fallback = (fallback_name or "").strip()
        if not fallback:
            return None
        pkg_name = fallback
    return pkg_name, ecosystem


def _sbom_osv_target(
    *,
    name: str | None,
    version: str | None,
    language: str | None,
    purl: str | None,
) -> tuple[str, str] | None:
    from_purl = _purl_to_osv_target(purl=purl, fallback_name=name)
    if from_purl:
        return from_purl
    ecosystem = _infer_ecosystem_for_sbom(name=name, version=version, language=language)
    pkg_name = (name or "").strip()
    if not ecosystem or not pkg_name:
        return None
    return pkg_name, ecosystem


def _severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _normalize_severity(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return _severity_from_cvss(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            as_float = float(text)
            return _severity_from_cvss(as_float)
        except Exception:
            pass
        return _SEVERITY_MAP.get(text.lower(), text.upper()[:32])
    return None


def _severity_from_details(details: Any) -> str | None:
    if not isinstance(details, dict):
        return None
    direct = (
        _normalize_severity(details.get("severity"))
        or _normalize_severity(details.get("priority"))
        or _normalize_severity(details.get("impact"))
        or _normalize_severity(details.get("cvss3"))
    )
    if direct:
        return direct

    cvss = details.get("cvss")
    if isinstance(cvss, dict):
        from_cvss = _normalize_severity(cvss.get("score") or cvss.get("baseScore"))
        if from_cvss:
            return from_cvss

    releases = details.get("releases")
    if isinstance(releases, dict):
        for rel in releases.values():
            if isinstance(rel, dict):
                urgency = _normalize_severity(rel.get("urgency"))
                if urgency:
                    return urgency
    return None


def _severity_rank(value: str | None) -> int:
    sev = (value or "UNKNOWN").strip().upper()
    if sev == "CRITICAL":
        return 4
    if sev == "HIGH":
        return 3
    if sev == "MEDIUM":
        return 2
    if sev == "LOW":
        return 1
    return 0


def _effective_recent_window_days() -> int:
    settings = get_settings()
    years = max(0, int(settings.vuln_feed_recent_window_years or 0))
    if years > 0:
        return years * 365
    return max(0, int(settings.vuln_feed_recent_window_days or 0))


def _record_sort_key(rec: dict[str, Any]) -> tuple[int, datetime]:
    severity = rec.get("severity") or _severity_from_details(rec.get("details") or {})
    when = rec.get("modified_at") or rec.get("published_at") or datetime.min
    if not isinstance(when, datetime):
        when = datetime.min
    return (_severity_rank(severity), when)


def _apply_feed_curation(
    source: str, records: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    settings = get_settings()
    raw_count = len(records)
    if raw_count == 0:
        return [], {"raw_fetched_items": 0, "filtered_by_age": 0, "filtered_by_cap": 0}

    filtered_by_age = 0
    filtered_by_cap = 0

    curated = records
    window_days = _effective_recent_window_days()
    if window_days > 0:
        cutoff = _utc_now() - timedelta(days=window_days)
        age_filtered: list[dict[str, Any]] = []
        for rec in curated:
            when = rec.get("modified_at") or rec.get("published_at")
            if isinstance(when, datetime) and when < cutoff:
                filtered_by_age += 1
                continue
            age_filtered.append(rec)
        curated = age_filtered

    curated = sorted(curated, key=_record_sort_key, reverse=True)

    if source == SOURCE_OSV:
        per_ecosystem_cap = max(0, settings.vuln_feed_osv_max_records_per_ecosystem)
        if per_ecosystem_cap > 0:
            eco_counts: dict[str, int] = {}
            eco_curated: list[dict[str, Any]] = []
            for rec in curated:
                eco = str(rec.get("ecosystem") or "unknown").strip().lower()
                current = eco_counts.get(eco, 0)
                if current >= per_ecosystem_cap:
                    filtered_by_cap += 1
                    continue
                eco_counts[eco] = current + 1
                eco_curated.append(rec)
            curated = eco_curated

        linux_kernel_cap = max(0, settings.vuln_feed_linux_kernel_max_records)
        if linux_kernel_cap > 0:
            kernel_count = 0
            kernel_curated: list[dict[str, Any]] = []
            for rec in curated:
                pkg_name = str(rec.get("package_name") or "").strip().lower()
                eco = str(rec.get("ecosystem") or "").strip().lower()
                is_kernel = "kernel" in pkg_name or eco in {"linux", "kernel"}
                if is_kernel:
                    if kernel_count >= linux_kernel_cap:
                        filtered_by_cap += 1
                        continue
                    kernel_count += 1
                kernel_curated.append(rec)
            curated = kernel_curated

    max_records = max(0, settings.vuln_feed_max_records_per_source)
    if max_records > 0 and len(curated) > max_records:
        filtered_by_cap += len(curated) - max_records
        curated = curated[:max_records]

    return curated, {
        "raw_fetched_items": raw_count,
        "filtered_by_age": filtered_by_age,
        "filtered_by_cap": filtered_by_cap,
    }


def _severity_from_osv(v: dict[str, Any]) -> str | None:
    severity = v.get("severity")
    if isinstance(severity, list) and severity:
        first = severity[0] or {}
        if isinstance(first, dict):
            score = first.get("score")
            parsed = _normalize_severity(score)
            if parsed:
                return parsed
    dbs = v.get("database_specific")
    if isinstance(dbs, dict):
        sev = _normalize_severity(dbs.get("severity"))
        if sev:
            return sev
    cvss_v3 = v.get("database_specific", {}).get("cvss", {}).get("score") if isinstance(v.get("database_specific"), dict) else None
    cvss_sev = _normalize_severity(cvss_v3)
    if cvss_sev:
        return cvss_sev
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
                "severity": (
                    "CRITICAL"
                    if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"
                    else "HIGH"
                ),
                "title": item.get("vulnerabilityName"),
                "details": item,
                "published_at": _to_dt(item.get("dateAdded")),
                "modified_at": _to_dt(payload.get("dateReleased")),
            }
        )
    return normalized


def _normalize_redhat(cve_ids: list[dict[str, Any] | str]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in cve_ids:
        if isinstance(item, dict):
            cve = item.get("CVE") or item.get("name") or item.get("id")
            severity = _normalize_severity(item.get("severity"))
            details = item
        else:
            cve = item
            severity = None
            details = {"cve": cve}
        if not isinstance(cve, str) or not cve.strip():
            continue
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
                "severity": severity,
                "title": None,
                "details": details,
                "published_at": None,
                "modified_at": None,
            }
        )
    return normalized


def _normalize_debian(payload: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    count = 0
    for top_key, top_value in payload.items():
        if count >= limit:
            break
        if not isinstance(top_key, str) or not isinstance(top_value, dict):
            continue

        # Debian tracker format is package -> CVE -> advisory payload.
        if top_key.startswith("CVE-"):
            cve_id = top_key
            details = top_value
            package_name = None
            out.append(
                {
                    "source": SOURCE_DEBIAN,
                    "record_key": _record_key([cve_id]),
                    "vulnerability_id": cve_id[:128],
                    "aliases": [cve_id],
                    "package_name": package_name,
                    "ecosystem": "Debian",
                    "version": None,
                    "severity": None,
                    "title": details.get("description")
                    if isinstance(details.get("description"), str)
                    else None,
                    "details": details,
                    "published_at": None,
                    "modified_at": None,
                }
            )
            count += 1
            continue

        package_name = top_key
        advisories = top_value
        for cve_id, advisory in advisories.items():
            if count >= limit:
                break
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            details = advisory if isinstance(advisory, dict) else {}
            severity = None
            releases = details.get("releases")
            if isinstance(releases, dict):
                for rel in releases.values():
                    if isinstance(rel, dict):
                        urgency = rel.get("urgency")
                        normalized_urgency = _normalize_severity(urgency)
                        if normalized_urgency:
                            severity = normalized_urgency
                            break
            out.append(
                {
                    "source": SOURCE_DEBIAN,
                    "record_key": _record_key([cve_id, package_name]),
                    "vulnerability_id": cve_id[:128],
                    "aliases": [cve_id],
                    "package_name": package_name[:256],
                    "ecosystem": "Debian",
                    "version": None,
                    "severity": severity,
                    "title": details.get("description")
                    if isinstance(details.get("description"), str)
                    else None,
                    "details": details,
                    "published_at": None,
                    "modified_at": None,
                }
            )
            count += 1
    return out


def _stream_debian_records_from_json(json_file: BinaryIO, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    count = 0
    max_items = max(1, limit)
    for top_key, top_value in ijson.kvitems(json_file, "", use_float=True):
        if count >= max_items:
            break
        if not isinstance(top_key, str) or not isinstance(top_value, dict):
            continue

        # Debian tracker format is package -> CVE -> advisory payload.
        if top_key.startswith("CVE-"):
            cve_id = top_key
            details = top_value
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
                    "title": details.get("description")
                    if isinstance(details.get("description"), str)
                    else None,
                    "details": details,
                    "published_at": None,
                    "modified_at": None,
                }
            )
            count += 1
            continue

        package_name = top_key
        advisories = top_value
        for cve_id, advisory in advisories.items():
            if count >= max_items:
                break
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            details = advisory if isinstance(advisory, dict) else {}
            severity = None
            releases = details.get("releases")
            if isinstance(releases, dict):
                for rel in releases.values():
                    if isinstance(rel, dict):
                        normalized_urgency = _normalize_severity(rel.get("urgency"))
                        if normalized_urgency:
                            severity = normalized_urgency
                            break
            out.append(
                {
                    "source": SOURCE_DEBIAN,
                    "record_key": _record_key([cve_id, package_name]),
                    "vulnerability_id": cve_id[:128],
                    "aliases": [cve_id],
                    "package_name": package_name[:256],
                    "ecosystem": "Debian",
                    "version": None,
                    "severity": severity,
                    "title": details.get("description")
                    if isinstance(details.get("description"), str)
                    else None,
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
                "severity": _normalize_severity(row.get("priority")),
                "title": row.get("description"),
                "details": row,
                "published_at": _to_dt(row.get("published")),
                "modified_at": _to_dt(row.get("updated_at") or row.get("modified")),
            }
        )
    return out


def _stream_ubuntu_records_from_json(json_file: BinaryIO, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    max_items = max(1, limit)
    for row in ijson.items(json_file, "cves.item", use_float=True):
        if len(out) >= max_items:
            break
        if not isinstance(row, dict):
            continue
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
                "severity": _normalize_severity(row.get("priority")),
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
    state: dict[str, Any] | None = None,
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
    row.state = state or {}
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


async def _get_source_state(db: AsyncSession, source: str) -> dict[str, Any]:
    row = await db.scalar(
        select(VulnFeedSource).where(VulnFeedSource.source == source).limit(1)
    )
    if row and isinstance(row.state, dict):
        return row.state
    return {}


def _safe_cursor(value: Any, total: int) -> int:
    if total <= 0:
        return 0
    try:
        return int(value) % total
    except Exception:
        return 0


def _next_cursor(current: int, consumed: int, total: int) -> int:
    if total <= 0:
        return 0
    return (max(0, current) + max(0, consumed)) % total


async def _fetch_osv_records(
    client: httpx.AsyncClient, db: AsyncSession
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    settings = get_settings()
    max_queries = max(0, settings.vuln_feed_osv_max_queries)
    if max_queries == 0:
        return [], _checksum_for_payload([]), {"osv_cursor": 0}

    source_state = await _get_source_state(db, SOURCE_OSV)
    total_candidates = int(
        (
            await db.execute(
                select(func.count(SbomPackage.id)).where(
                    SbomPackage.name.is_not(None),
                    SbomPackage.version.is_not(None),
                )
            )
        ).scalar_one()
        or 0
    )
    if total_candidates <= 0:
        return [], _checksum_for_payload([]), {"osv_cursor": 0}

    cursor = _safe_cursor(source_state.get("osv_cursor"), total_candidates)
    query_order = select(
        SbomPackage.name, SbomPackage.version, SbomPackage.language, SbomPackage.purl
    ).where(
        SbomPackage.name.is_not(None),
        SbomPackage.version.is_not(None),
    ).order_by(
        func.coalesce(SbomPackage.tenant_id, ""),
        func.coalesce(SbomPackage.component, ""),
        func.lower(SbomPackage.name),
        func.coalesce(SbomPackage.version, ""),
    )
    first_batch = (
        (await db.execute(query_order.offset(cursor).limit(max_queries))).all()
    )
    sbom_rows = list(first_batch)
    if 0 < len(sbom_rows) < max_queries and total_candidates > len(sbom_rows):
        remaining = max_queries - len(sbom_rows)
        wrapped = (await db.execute(query_order.limit(remaining))).all()
        sbom_rows.extend(wrapped)
    # Guard against duplicate candidates when the SBOM set is smaller than max_queries.
    seen_sbom: set[tuple[str, str, str | None, str | None]] = set()
    unique_rows: list[tuple[str, str, str | None, str | None]] = []
    for name, version, language, purl in sbom_rows:
        key = (
            str(name),
            str(version),
            language if isinstance(language, str) else None,
            purl if isinstance(purl, str) else None,
        )
        if key in seen_sbom:
            continue
        seen_sbom.add(key)
        unique_rows.append((key[0], key[1], key[2], key[3]))
    sbom_rows = unique_rows

    queries = []
    for name, version, language, purl in sbom_rows:
        if not name or not version:
            continue
        target = _sbom_osv_target(
            name=name, version=version, language=language, purl=purl
        )
        if not target:
            continue
        package_name, ecosystem = target
        queries.append(
            {
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version,
            }
        )
    if not queries:
        return [], _checksum_for_payload([]), {"osv_cursor": cursor}

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
    next_cursor = _next_cursor(cursor, len(sbom_rows), total_candidates)
    return normalized, _checksum_for_payload(payload), {"osv_cursor": next_cursor}


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
    ids: list[dict[str, Any] | str] = []
    if isinstance(payload, list):
        for item in payload[:max_items]:
            if isinstance(item, str) and item.strip():
                ids.append(item.strip())
            elif isinstance(item, dict):
                ids.append(item)
    return _normalize_redhat(ids), _checksum_for_payload(payload)


async def _fetch_debian_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    with tempfile.TemporaryFile("w+b") as feed_file:
        async with client.stream(
            "GET", "https://security-tracker.debian.org/tracker/data/json"
        ) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                if chunk:
                    feed_file.write(chunk)
        feed_file.seek(0)
        normalized = _stream_debian_records_from_json(feed_file, max_items)
    return normalized, _checksum_for_feed_records(normalized)


async def _fetch_ubuntu_records(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str]:
    settings = get_settings()
    max_items = max(1, settings.vuln_feed_max_records_per_source)
    with tempfile.TemporaryFile("w+b") as feed_file:
        async with client.stream("GET", "https://ubuntu.com/security/cves.json") as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                if chunk:
                    feed_file.write(chunk)
        feed_file.seek(0)
        normalized = _stream_ubuntu_records_from_json(feed_file, max_items)
    return normalized, _checksum_for_feed_records(normalized)


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
    source_state: dict[str, Any] | None = await _get_source_state(db, source)
    raw_fetched_items = 0
    filtered_by_age = 0
    filtered_by_cap = 0

    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            if source == SOURCE_OSV:
                records, checksum, source_state = await _fetch_osv_records(client, db)
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

        records, curation_stats = _apply_feed_curation(source, records)
        raw_fetched_items = curation_stats["raw_fetched_items"]
        filtered_by_age = curation_stats["filtered_by_age"]
        filtered_by_cap = curation_stats["filtered_by_cap"]
        inserted, updated = await _upsert_records(
            db, source=source, run_id=run_id, records=records
        )
        run.status = "completed"
        run.stats = {
            "raw_fetched_items": raw_fetched_items,
            "fetched_items": len(records),
            "filtered_by_age": filtered_by_age,
            "filtered_by_cap": filtered_by_cap,
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
            state=source_state,
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
            raw_fetched_items=raw_fetched_items,
            filtered_by_age=filtered_by_age,
            filtered_by_cap=filtered_by_cap,
            failed=False,
            checksum=checksum,
            etag=etag,
        )
    except Exception as exc:
        err = str(exc)
        run.status = "failed"
        run.error = err[:4000]
        run.completed_at = _utc_now()
        run.stats = {
            "raw_fetched_items": raw_fetched_items,
            "fetched_items": len(records),
            "filtered_by_age": filtered_by_age,
            "filtered_by_cap": filtered_by_cap,
            "inserted": 0,
            "updated": 0,
        }
        await _upsert_source_state(
            db,
            source=source,
            status="failed",
            item_count=0,
            checksum=checksum,
            etag=etag,
            error=err,
            state=source_state,
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
            raw_fetched_items=raw_fetched_items,
            filtered_by_age=filtered_by_age,
            filtered_by_cap=filtered_by_cap,
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
                "raw_fetched_items": source_stats.raw_fetched_items,
                "fetched_items": source_stats.fetched_items,
                "filtered_by_age": source_stats.filtered_by_age,
                "filtered_by_cap": source_stats.filtered_by_cap,
                "inserted": source_stats.inserted,
                "updated": source_stats.updated,
                "failed": source_stats.failed,
                "error": source_stats.error,
                "checksum": source_stats.checksum,
                "etag": source_stats.etag,
            }
        )
    materialized = await materialize_feed_matches_to_findings(
        db, trace_id=run_trace_id, actor_id=actor_id
    )
    return {
        "enabled": True,
        "sources": _enabled_sources(),
        "stats": stats,
        "materialization": materialized,
    }


async def prune_feed_storage(
    db: AsyncSession,
    *,
    trace_id: str | None = None,
    actor_id: str = "system",
) -> dict[str, int]:
    settings = get_settings()
    now = _utc_now()
    run_trace_id = trace_id or new_trace_id()
    deleted_runs = 0
    deleted_records = 0

    runs_days = max(0, int(settings.vuln_feed_runs_retention_days or 0))
    if runs_days > 0:
        runs_cutoff = now - timedelta(days=runs_days)
        result = await db.execute(
            delete(VulnFeedRun).where(VulnFeedRun.started_at < runs_cutoff)
        )
        deleted_runs = int(result.rowcount or 0)

    records_days = max(0, int(settings.vuln_feed_records_retention_days or 0))
    if records_days > 0:
        records_cutoff = now - timedelta(days=records_days)
        result = await db.execute(
            delete(VulnFeedRecord).where(VulnFeedRecord.fetched_at < records_cutoff)
        )
        deleted_records = int(result.rowcount or 0)

    payload = {
        "deleted_runs": deleted_runs,
        "deleted_records": deleted_records,
        "runs_retention_days": runs_days,
        "records_retention_days": records_days,
    }
    await emit_audit_event(
        db,
        trace_id=run_trace_id,
        event_type="vuln_feed.retention.completed",
        actor_type="user" if actor_id != "system" else "system",
        actor_id=actor_id,
        decision_name="vuln_feed_retention",
        decision_reason_code="scheduled_cleanup",
        decision_confidence="high",
        decision_result="completed",
        data=payload,
    )
    return payload


def _finding_severity(value: str | None) -> Severity:
    sev = (value or "").strip().upper()
    if sev == "CRITICAL":
        return Severity.Critical
    if sev == "HIGH":
        return Severity.High
    if sev == "MEDIUM":
        return Severity.Medium
    if sev == "LOW":
        return Severity.Low
    return Severity.Informational


def _is_open_lifecycle_status(status: Status) -> bool:
    return status in {
        Status.Open,
        Status.Reopened,
        Status.SyncedToTracker,
        Status.InReview,
    }


def _build_materialized_description(record: dict[str, Any]) -> str:
    details = record.get("details") or {}
    base = (
        record.get("title")
        or details.get("description")
        or details.get("summary")
        or details.get("vulnerabilityName")
    )
    if isinstance(base, str) and base.strip():
        return base.strip()[:4000]
    return (
        f"Matched feed advisory {record.get('vulnerability_id') or record.get('record_key')} "
        f"to SBOM package {record.get('package_name') or 'unknown'}."
    )[:4000]


def _normalize_ecosystem(value: str | None) -> str:
    return (value or "").strip().lower()


def _match_strategy(
    *,
    sbom_name: str | None,
    sbom_version: str | None,
    sbom_language: str | None,
    sbom_purl: str | None,
    sbom_purl_source: str | None = None,
    sbom_purl_confidence: str | None = None,
    advisory_package: str | None,
    advisory_ecosystem: str | None,
    advisory_version: str | None,
) -> tuple[str, str]:
    sbom_name = (sbom_name or "").strip().lower()
    adv_name = (advisory_package or "").strip().lower()
    if not sbom_name or not adv_name or sbom_name != adv_name:
        return ("name_mismatch", "low")

    purl_target = _purl_to_osv_target(purl=sbom_purl, fallback_name=sbom_name)
    sbom_eco = _normalize_ecosystem(
        (purl_target[1] if purl_target else None)
        or _ECOSYSTEM_BY_LANGUAGE.get((sbom_language or "").lower())
        or sbom_language
    )
    adv_eco = _normalize_ecosystem(advisory_ecosystem)
    ecosystem_aligned = bool(sbom_eco and adv_eco and sbom_eco == adv_eco)

    sbom_version = (sbom_version or "").strip()
    adv_version = (advisory_version or "").strip()
    if adv_version and sbom_version and adv_version == sbom_version:
        if ecosystem_aligned:
            strategy, confidence = ("name+version+ecosystem", "high")
        else:
            strategy, confidence = ("name+version", "medium")
        if (
            (sbom_purl_source or "").strip().lower() == "derived_probe"
            and (sbom_purl_confidence or "").strip().lower() == "medium"
            and confidence != "low"
        ):
            return (f"{strategy}+probe", "low")
        return (strategy, confidence)
    if adv_version and sbom_version and adv_version != sbom_version:
        return ("version_mismatch", "low")
    if ecosystem_aligned:
        strategy, confidence = ("name+ecosystem_no_version", "medium")
    else:
        strategy, confidence = ("advisory-no-version", "low")
    if (
        (sbom_purl_source or "").strip().lower() == "derived_probe"
        and (sbom_purl_confidence or "").strip().lower() == "medium"
        and confidence != "low"
    ):
        return (f"{strategy}+probe", "low")
    return (strategy, confidence)


def _canonicalize_feed_match_image(value: str | None) -> str:
    """Apply the same canonicalization HTTP ingest uses, so feed-match
    findings land on the same asset key as Aikido/SBOM findings.

    SbomPackage.component values can be full OCI refs (e.g.
    ``ghcr.io/kamiwaza-internal/foo:1.5.28``) when the local scanner
    stamped them. Without normalization, vuln_feed_match findings show
    up under shadow assets with un-stripped registry prefixes.
    """
    raw = (value or "").strip()
    if not raw:
        return raw
    if infer_asset_kind(raw, "") != "container":
        return raw
    return apply_container_asset_path_aliases(
        normalize_container_ref(raw).canonical_asset_key
    )


async def _ensure_feed_match_asset_record(
    db: AsyncSession, asset_id: str | None
) -> bool:
    """Backfill an ``Asset`` row for a feed-match finding's image.

    Mirrors the SBOM-side and Aikido-sync helpers so vuln-feed-match
    findings appear in the assets list rather than as orphans.
    """
    if not asset_id or not str(asset_id).strip():
        return False
    aid = str(asset_id).strip()
    existing = await db.get(Asset, aid)
    if existing:
        return False
    inferred = infer_asset_kind(aid, "")
    kind = inferred if inferred in ("container", "repo") else "package"
    db.add(
        Asset(
            id=aid,
            name=aid,
            type=kind,
            source=SOURCE_VULN_FEED_MATCH,
            branch=None,
            tag=None,
        )
    )
    return True


def _materialized_finding_payload(
    *,
    asset_id: str,
    sbom_pkg: SbomPackage,
    record: dict[str, Any],
    advisory_source: str,
    strategy: str,
    confidence: str,
) -> dict[str, Any]:
    cve_id = (
        record.get("vulnerability_id")
        or (record.get("aliases") or [None])[0]
        or record.get("record_key")
        or "UNKNOWN"
    )
    tenant_scope = (sbom_pkg.tenant_id or "global").strip()
    fingerprint = make_fingerprint(
        str(cve_id),
        f"{sbom_pkg.name}|{sbom_pkg.version}|{tenant_scope}|{strategy}",
        image=asset_id,
        source_name=SOURCE_VULN_FEED_MATCH,
    )
    return {
        "fingerprint_id": fingerprint,
        "cve_id": str(cve_id)[:128],
        "severity": _finding_severity(record.get("severity")),
        "component_base": (sbom_pkg.name or "")[:256] or None,
        "component": f"{sbom_pkg.name} {sbom_pkg.version}"[:512],
        "ecosystem": (record.get("ecosystem") or sbom_pkg.language or "")[:64] or None,
        "image": asset_id[:256],
        "title": (record.get("title") or str(cve_id))[:512],
        "description": _build_materialized_description(record),
        "source": SOURCE_VULN_FEED_MATCH,
        "audit_note": (
            f"Feed source={advisory_source}; package={sbom_pkg.name}@{sbom_pkg.version}; "
            f"asset={asset_id}; strategy={strategy}; confidence={confidence}"
        )[:512],
        "correlation_key": f"feed_match:{advisory_source}:{strategy}:{record.get('record_key')}"[
            :255
        ],
        "correlation_confidence": confidence[:32],
        "tracker_comment": False,
        "tenant_id": sbom_pkg.tenant_id,
        "sources": [
            {
                "name": SOURCE_VULN_FEED_MATCH,
                "importedAt": _now_iso(),
                "feedSource": advisory_source,
                "matchStrategy": strategy,
                "matchConfidence": confidence,
                "matchedPackage": (sbom_pkg.name or "")[:256],
                "matchedVersion": (sbom_pkg.version or "")[:128],
                "matchedAsset": asset_id[:256],
            },
            {"name": advisory_source, "importedAt": _now_iso()},
        ],
    }


async def materialize_feed_matches_to_findings(
    db: AsyncSession,
    *,
    trace_id: str,
    actor_id: str = "system",
) -> dict[str, int]:
    settings = get_settings()
    include_low_confidence = bool(settings.vuln_feed_match_include_low_confidence)
    sbom_rows = (
        (await db.execute(select(SbomPackage).where(SbomPackage.component.is_not(None))))
        .scalars()
        .all()
    )
    if not sbom_rows:
        return {
            "created": 0,
            "updated": 0,
            "reopened": 0,
            "resolved": 0,
            "matched": 0,
            "excluded_low_confidence": 0,
            "excluded_version_mismatch": 0,
        }

    alias_rows = (
        (await db.execute(select(AssetAlias.source_asset_id, AssetAlias.canonical_asset_id)))
        .all()
    )
    source_to_canonical = {
        str(src).strip(): str(canon).strip()
        for src, canon in alias_rows
        if isinstance(src, str) and isinstance(canon, str) and src.strip() and canon.strip()
    }

    package_names = sorted(
        {(row.name or "").strip().lower() for row in sbom_rows if (row.name or "").strip()}
    )
    if not package_names:
        return {
            "created": 0,
            "updated": 0,
            "reopened": 0,
            "resolved": 0,
            "matched": 0,
            "excluded_low_confidence": 0,
            "excluded_version_mismatch": 0,
        }

    advisory_rows = (
        (
            await db.execute(
                select(VulnFeedRecord).where(
                    func.lower(VulnFeedRecord.package_name).in_(package_names)
                )
            )
        )
        .scalars()
        .all()
    )
    advisories_by_package: dict[str, list[VulnFeedRecord]] = {}
    for row in advisory_rows:
        pkg = (row.package_name or "").strip().lower()
        if not pkg:
            continue
        advisories_by_package.setdefault(pkg, []).append(row)

    candidates: dict[str, dict[str, Any]] = {}
    excluded_low_confidence = 0
    excluded_version_mismatch = 0
    for pkg in sbom_rows:
        package_key = (pkg.name or "").strip().lower()
        if not package_key:
            continue
        asset_id_raw = (pkg.component or "").strip()
        if not asset_id_raw:
            continue
        # Canonicalize first (apply container alias rules), then resolve
        # asset_aliases so existing manual merges are honored too.
        asset_id_canonical = _canonicalize_feed_match_image(asset_id_raw)
        asset_id = source_to_canonical.get(
            asset_id_canonical, asset_id_canonical
        )
        for advisory in advisories_by_package.get(package_key, []):
            strategy, confidence = _match_strategy(
                sbom_name=pkg.name,
                sbom_version=pkg.version,
                sbom_language=pkg.language,
                sbom_purl=pkg.purl,
                sbom_purl_source=getattr(pkg, "purl_source", None),
                sbom_purl_confidence=getattr(pkg, "purl_confidence", None),
                advisory_package=advisory.package_name,
                advisory_ecosystem=advisory.ecosystem,
                advisory_version=advisory.version,
            )
            if strategy == "version_mismatch":
                excluded_version_mismatch += 1
                continue
            if strategy == "name_mismatch":
                continue
            if confidence == "low" and not include_low_confidence:
                excluded_low_confidence += 1
                continue
            serialized = _serialize_feed_record(advisory)
            payload = _materialized_finding_payload(
                asset_id=asset_id,
                sbom_pkg=pkg,
                record=serialized,
                advisory_source=advisory.source,
                strategy=strategy,
                confidence=confidence,
            )
            candidates[payload["fingerprint_id"]] = payload

    if not candidates:
        stale_rows = (
            (
                await db.execute(
                    select(Finding).where(Finding.source == SOURCE_VULN_FEED_MATCH)
                )
            )
            .scalars()
            .all()
        )
        resolved = 0
        for row in stale_rows:
            if not _is_open_lifecycle_status(row.status):
                continue
            row.previous_status = row.status.value
            row.status = Status.Resolved
            audit = list(row.audit or [])
            audit.append(
                {
                    "ts": _now_iso(),
                    "user": actor_id,
                    "action": "Feed advisory auto-resolved",
                    "note": "No longer matched by current SBOM/feed correlation.",
                }
            )
            row.audit = audit
            resolved += 1
        return {
            "created": 0,
            "updated": 0,
            "reopened": 0,
            "resolved": resolved,
            "matched": 0,
            "excluded_low_confidence": excluded_low_confidence,
            "excluded_version_mismatch": excluded_version_mismatch,
        }

    candidate_fps = sorted(candidates.keys())
    existing_rows = (
        (
            await db.execute(
                select(Finding).where(Finding.fingerprint_id.in_(candidate_fps))
            )
        )
        .scalars()
        .all()
    )
    existing_by_fp = {row.fingerprint_id: row for row in existing_rows}

    created = 0
    updated = 0
    reopened = 0
    for fp, payload in candidates.items():
        row = existing_by_fp.get(fp)
        now_iso = _now_iso()
        await _ensure_feed_match_asset_record(db, payload.get("image"))
        if row is None:
            finding = Finding(
                id=f"f-{fp[:8]}",
                finding_type=FindingType.SCA,
                fingerprint_id=fp,
                cve_id=payload["cve_id"],
                severity=payload["severity"],
                status=Status.Open,
                component_base=payload["component_base"],
                component=payload["component"],
                image=payload["image"],
                ecosystem=payload["ecosystem"],
                title=payload["title"],
                description=payload["description"],
                source=payload["source"],
                correlation_key=payload["correlation_key"],
                correlation_confidence=payload["correlation_confidence"],
                tracker_comment=payload["tracker_comment"],
                sources=payload["sources"],
                tenant_id=payload["tenant_id"],
                audit=[
                    {
                        "ts": now_iso,
                        "user": actor_id,
                        "action": "Feed advisory materialized to finding",
                        "note": payload["audit_note"],
                    }
                ],
            )
            db.add(finding)
            created += 1
            continue

        row.cve_id = payload["cve_id"]
        row.severity = payload["severity"]
        row.component_base = payload["component_base"]
        row.component = payload["component"]
        row.image = payload["image"]
        row.ecosystem = payload["ecosystem"]
        row.title = payload["title"]
        row.description = payload["description"]
        row.source = payload["source"]
        row.correlation_key = payload["correlation_key"]
        row.correlation_confidence = payload["correlation_confidence"]
        row.tracker_comment = payload["tracker_comment"]
        row.tenant_id = payload["tenant_id"]
        row.sources = payload["sources"]
        if row.status in {Status.Resolved, Status.Mitigated}:
            row.previous_status = row.status.value
            row.status = Status.Reopened
            reopened += 1
        audit = list(row.audit or [])
        audit.append(
            {
                "ts": now_iso,
                "user": actor_id,
                "action": "Feed advisory finding refreshed",
                "note": payload["audit_note"],
            }
        )
        row.audit = audit
        updated += 1

    stale_rows = (
        (
            await db.execute(
                select(Finding).where(Finding.source == SOURCE_VULN_FEED_MATCH)
            )
        )
        .scalars()
        .all()
    )
    resolved = 0
    active_fps = set(candidate_fps)
    for row in stale_rows:
        if row.fingerprint_id in active_fps:
            continue
        if not _is_open_lifecycle_status(row.status):
            continue
        row.previous_status = row.status.value
        row.status = Status.Resolved
        audit = list(row.audit or [])
        audit.append(
            {
                "ts": _now_iso(),
                "user": actor_id,
                "action": "Feed advisory auto-resolved",
                "note": "No longer matched by current SBOM/feed correlation.",
            }
        )
        row.audit = audit
        resolved += 1

    strategy_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for payload in candidates.values():
        strategy = str(payload.get("correlation_key") or "")
        confidence = str(payload.get("correlation_confidence") or "unknown")
        if strategy:
            strategy_tag = strategy.split(":", 4)[2] if ":" in strategy else strategy
            strategy_counts[strategy_tag] = strategy_counts.get(strategy_tag, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

    await emit_audit_event(
        db,
        trace_id=trace_id,
        event_type="vuln_feed.materialize.completed",
        actor_type="user" if actor_id != "system" else "system",
        actor_id=actor_id,
        decision_name="vuln_feed_materialization",
        decision_reason_code="sbom_feed_correlation",
        decision_confidence="high",
        decision_result="completed",
        data={
            "created": created,
            "updated": updated,
            "reopened": reopened,
            "resolved": resolved,
            "matched": len(candidates),
            "excluded_low_confidence": excluded_low_confidence,
            "excluded_version_mismatch": excluded_version_mismatch,
            "strategy_counts": strategy_counts,
            "confidence_counts": confidence_counts,
        },
    )
    return {
        "created": created,
        "updated": updated,
        "reopened": reopened,
        "resolved": resolved,
        "matched": len(candidates),
        "excluded_low_confidence": excluded_low_confidence,
        "excluded_version_mismatch": excluded_version_mismatch,
    }


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
                "state": state.state or {},
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
                select(
                    SbomPackage.name,
                    SbomPackage.version,
                    SbomPackage.language,
                    SbomPackage.purl,
                ).limit(
                    max(1, package_limit)
                )
            )
        )
        .all()
    )

    queries = []
    for name, version, language, purl in sbom_rows:
        if not name or not version:
            continue
        target = _sbom_osv_target(
            name=name,
            version=version,
            language=language,
            purl=purl,
        )
        if not target:
            continue
        package_name, ecosystem = target
        queries.append(
            {
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version,
            }
        )
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
    records = [_serialize_feed_record(row) for row in rows]
    return {"total": total, "count": len(records), "records": records}


def _serialize_feed_record(row: VulnFeedRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "source": row.source,
        "record_key": row.record_key,
        "vulnerability_id": row.vulnerability_id,
        "aliases": row.aliases or [],
        "package_name": row.package_name,
        "ecosystem": row.ecosystem,
        "version": row.version,
        "severity": row.severity or _severity_from_details(row.details),
        "title": row.title,
        "details": row.details or {},
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "modified_at": row.modified_at.isoformat() if row.modified_at else None,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
        "run_id": row.run_id,
    }


async def get_asset_vuln_intel(
    db: AsyncSession,
    *,
    asset_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    asset = (asset_id or "").strip()
    if not asset:
        return {
            "asset_id": "",
            "related_asset_ids": [],
            "sbom_package_count": 0,
            "matched_advisory_count": 0,
            "severity_breakdown": {},
            "source_breakdown": {},
            "matches": [],
        }

    related_ids: set[str] = {asset}
    canonical = await db.scalar(
        select(AssetAlias.canonical_asset_id).where(AssetAlias.source_asset_id == asset)
    )
    if isinstance(canonical, str) and canonical.strip():
        related_ids.add(canonical.strip())
    rows = (
        (
            await db.execute(
                select(AssetAlias.source_asset_id).where(
                    AssetAlias.canonical_asset_id.in_(sorted(related_ids))
                )
            )
        )
        .scalars()
        .all()
    )
    for src in rows:
        if isinstance(src, str) and src.strip():
            related_ids.add(src.strip())

    ids = sorted(related_ids)
    sbom_rows = (
        (
            await db.execute(
                select(SbomPackage)
                .where(
                    or_(
                        SbomPackage.component.in_(ids),
                        *[SbomPackage.component.ilike(f"%{x}%") for x in ids],
                    )
                )
                .order_by(SbomPackage.updated_at.desc())
            )
        )
        .scalars()
        .all()
    )
    if not sbom_rows:
        return {
            "asset_id": asset,
            "related_asset_ids": ids,
            "sbom_package_count": 0,
            "matched_advisory_count": 0,
            "severity_breakdown": {},
            "source_breakdown": {},
            "matches": [],
        }

    pkg_versions: dict[str, set[str]] = {}
    sbom_refs: dict[str, list[dict[str, str | None]]] = {}
    for pkg in sbom_rows:
        name = (pkg.name or "").strip().lower()
        if not name:
            continue
        pkg_versions.setdefault(name, set())
        if isinstance(pkg.version, str) and pkg.version.strip():
            pkg_versions[name].add(pkg.version.strip())
        sbom_refs.setdefault(name, []).append(
            {
                "name": pkg.name,
                "version": pkg.version,
                "component": pkg.component,
                "language": pkg.language,
                "purl": pkg.purl,
                "purlSource": getattr(pkg, "purl_source", None),
                "purlConfidence": getattr(pkg, "purl_confidence", None),
            }
        )

    if not pkg_versions:
        return {
            "asset_id": asset,
            "related_asset_ids": ids,
            "sbom_package_count": 0,
            "matched_advisory_count": 0,
            "severity_breakdown": {},
            "source_breakdown": {},
            "matches": [],
        }

    advisory_rows = (
        (
            await db.execute(
                select(VulnFeedRecord)
                .where(func.lower(VulnFeedRecord.package_name).in_(sorted(pkg_versions)))
                .order_by(desc(VulnFeedRecord.fetched_at))
                .limit(max(1, min(1000, limit * 5)))
            )
        )
        .scalars()
        .all()
    )
    matches: list[dict[str, Any]] = []
    severity_breakdown: dict[str, int] = {}
    source_breakdown: dict[str, int] = {}
    seen_ids: set[int] = set()
    for row in advisory_rows:
        if row.id in seen_ids:
            continue
        package_key = (row.package_name or "").strip().lower()
        if not package_key or package_key not in pkg_versions:
            continue
        versions = pkg_versions.get(package_key) or set()
        advisory_version = (row.version or "").strip()
        if versions and advisory_version and advisory_version not in versions:
            continue
        seen_ids.add(row.id)
        record = _serialize_feed_record(row)
        matched_refs = sbom_refs.get(package_key, [])[:10]
        strategy = "advisory-no-version"
        confidence = "low"
        for ref in matched_refs:
            ref_strategy, ref_confidence = _match_strategy(
                sbom_name=ref.get("name"),
                sbom_version=ref.get("version"),
                sbom_language=ref.get("language"),
                sbom_purl=ref.get("purl"),
                sbom_purl_source=ref.get("purlSource"),
                sbom_purl_confidence=ref.get("purlConfidence"),
                advisory_package=row.package_name,
                advisory_ecosystem=row.ecosystem,
                advisory_version=row.version,
            )
            if ref_strategy in {"name_mismatch", "version_mismatch"}:
                continue
            strategy = ref_strategy
            confidence = ref_confidence
            if ref_confidence == "high":
                break
        record["matched_sbom_packages"] = matched_refs
        record["match_strategy"] = strategy
        record["match_confidence"] = confidence
        matches.append(record)
        sev = (record.get("severity") or "UNKNOWN").upper()
        severity_breakdown[sev] = int(severity_breakdown.get(sev, 0)) + 1
        src = (row.source or "unknown").strip() or "unknown"
        source_breakdown[src] = int(source_breakdown.get(src, 0)) + 1
        if len(matches) >= max(1, min(500, limit)):
            break

    return {
        "asset_id": asset,
        "related_asset_ids": ids,
        "sbom_package_count": len(sbom_rows),
        "matched_advisory_count": len(matches),
        "severity_breakdown": severity_breakdown,
        "source_breakdown": source_breakdown,
        "matches": matches,
    }
