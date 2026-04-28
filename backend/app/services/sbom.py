"""SBOM service — CycloneDX import, dedup by name+version. PRD §5.8."""

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, unquote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.finding import Finding, FindingType, Severity, Status
from app.models.sbom import SbomPackage, license_risk_tier
from app.services.asset_resolver import infer_asset_kind
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)


def _canonicalize_container_image(value: str | None) -> str | None:
    """Apply the same container ref canonicalization used by ingest's resolver.

    Strips digest, tag, and configured registry prefix so SBOM-derived License
    findings land on the same canonical asset key as the rest of ingest.
    """
    if not value:
        return value
    if infer_asset_kind(value, "") != "container":
        return value
    return apply_container_asset_path_aliases(
        normalize_container_ref(value).canonical_asset_key
    )


def _extract_metadata_tag_digest(doc: dict) -> tuple[str | None, str | None]:
    """Pull (tag, digest) from CycloneDX ``metadata.component`` for SBOM-derived findings.

    Mirrors parsers.cyclonedx._extract_sbom_tag_digest precedence: name suffix,
    version, PURL ``?tag=``/``@sha256:``. Defensive against varying SBOM emitters.
    """
    md = (doc or {}).get("metadata") or {}
    comp_meta = md.get("component") or {}
    if not isinstance(comp_meta, dict):
        return None, None
    name = str(comp_meta.get("name") or "").strip()
    version = str(comp_meta.get("version") or "").strip() or None
    purl = str(comp_meta.get("purl") or "").strip()

    tag: str | None = None
    digest: str | None = None
    s = name
    if "@sha256:" in s:
        s, _, dig = s.partition("@sha256:")
        digest = f"sha256:{dig.strip()}" if dig else None
    if s and ":" in s:
        last_slash = s.rfind("/")
        last_colon = s.rfind(":")
        if last_colon > last_slash:
            cand = s[last_colon + 1 :].strip()
            if cand and "/" not in cand:
                tag = cand
    if not tag and version:
        tag = version
    if not tag and purl and "?" in purl:
        for kv in purl.split("?", 1)[1].split("&"):
            if kv.startswith("tag="):
                tag = kv[4:].strip() or None
                break
    if not digest and "@sha256:" in purl:
        digest = (
            f"sha256:{purl.split('@sha256:', 1)[1].split('?', 1)[0].strip()}"
        )
    return tag, digest


def _clip(value: str | None, max_len: int) -> str | None:
    """Bound persisted string fields to DB column sizes."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    return v[:max_len]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _package_id(name: str, version: str, component: str) -> str:
    """Deterministic ID for dedup."""
    key = f"{name}|{version}|{component or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _extract_container_ref(component: dict, doc: dict) -> str:
    """Resolve stable container reference from CycloneDX properties/metadata."""
    props = component.get("properties") or []
    if isinstance(props, list):
        for p in props:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip().lower()
            val = str(p.get("value") or "").strip()
            if (
                name
                in {
                    "vat:container_ref",
                    "vat.container_ref",
                    "container_ref",
                    "container.image.ref",
                }
                and val
            ):
                return val
    # Backward compatibility: old scanner versions stamped container refs in group.
    group = str(component.get("group") or "").strip()
    if group:
        return group
    # Optional metadata-level fallback.
    md = doc.get("metadata") or {}
    md_props = md.get("properties") or []
    if isinstance(md_props, list):
        for p in md_props:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip().lower()
            val = str(p.get("value") or "").strip()
            if (
                name
                in {
                    "vat:container_ref",
                    "vat.container_ref",
                    "container_ref",
                    "container.image.ref",
                }
                and val
            ):
                return val
    md_component = md.get("component") or {}
    if isinstance(md_component, dict):
        name = str(md_component.get("name") or "").strip()
        if name:
            return name
    return ""


def _parse_cyclonedx(doc: dict) -> list[dict]:
    """
    Parse CycloneDX JSON (min 1.4). Returns list of package dicts.
    Handles components array and component.bomRef.
    """
    components = doc.get("components", [])
    if not components:
        return []
    out = []
    for c in components:
        purl = _extract_component_purl(c)
        name = c.get("name") or _name_from_purl(purl) or "unknown"
        version = c.get("version") or ""
        licenses = c.get("licenses", [])
        license_id = None
        if licenses:
            lic = licenses[0]
            if isinstance(lic, dict):
                lic_obj = lic.get("license", {})
                if isinstance(lic_obj, dict):
                    license_id = lic_obj.get("id") or lic_obj.get("name")
                else:
                    license_id = str(lic_obj) if lic_obj else None
            else:
                license_id = str(lic)
        component = _extract_container_ref(c, doc)
        language = c.get("language") or ""
        purl_source = "authoritative" if purl else None
        purl_confidence = "high" if purl else None
        if not purl:
            derived_purl, derived_confidence = _derive_purl(
                name=name,
                version=version,
                language=language,
            )
            if derived_purl:
                purl = derived_purl
                purl_source = "derived"
                purl_confidence = derived_confidence

        out.append(
            {
                "name": name,
                "version": version,
                "license_id": license_id,
                "component": str(component) if component else None,
                "language": str(language) if language else None,
                "purl": _clip(str(purl), 512) if purl else None,
                "purl_source": purl_source,
                "purl_confidence": purl_confidence,
            }
        )
    return out


def _extract_component_purl(component: dict) -> str | None:
    direct = component.get("purl")
    if isinstance(direct, str) and direct.strip().startswith("pkg:"):
        return direct.strip()
    bom_ref = component.get("bom-ref") or component.get("bomRef")
    if isinstance(bom_ref, str) and bom_ref.strip().startswith("pkg:"):
        return bom_ref.strip()
    return None


def _name_from_purl(purl: str | None) -> str | None:
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    if "?" in body:
        body = body.split("?", 1)[0]
    if "#" in body:
        body = body.split("#", 1)[0]
    if "/" not in body:
        return None
    purl_type, remainder = body.split("/", 1)
    path = remainder.split("@", 1)[0]
    path = unquote(path).strip()
    purl_type = (purl_type or "").strip().lower()
    if not path:
        return None
    if purl_type == "maven":
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
    if purl_type in {"pypi", "nuget", "gem", "cargo", "apk", "deb"}:
        return path.split("/")[-1]
    # npm scoped and golang module purls should retain path namespace.
    return path


_PURL_TYPE_BY_LANGUAGE = {
    "python": "pypi",
    "pypi": "pypi",
    "javascript": "npm",
    "typescript": "npm",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "go": "golang",
    "golang": "golang",
    "gomod": "golang",
    "java": "maven",
    "maven": "maven",
    "ruby": "gem",
    "rubygems": "gem",
    "rust": "cargo",
    "cargo": "cargo",
    "nuget": "nuget",
    "alpine": "apk",
    "apk": "apk",
    "debian": "deb",
    "deb": "deb",
}


def _derive_purl(
    *,
    name: str | None,
    version: str | None,
    language: str | None,
) -> tuple[str | None, str | None]:
    pkg = (name or "").strip()
    ver = (version or "").strip()
    lang = (language or "").strip().lower()
    if not pkg or not ver:
        return None, None

    # High-confidence package families with strong structural signals.
    if pkg.startswith(("github.com/", "golang.org/", "gopkg.in/")):
        return f"pkg:golang/{pkg}@{ver}", "high"
    # Many Go modules are hosted under domain-style prefixes beyond github/golang.org.
    first_segment = pkg.split("/", 1)[0].strip().lower()
    if "/" in pkg and "." in first_segment and " " not in pkg and "@" not in pkg:
        return f"pkg:golang/{pkg}@{ver}", "high"
    if pkg.startswith("@") and "/" in pkg:
        return f"pkg:npm/{quote(pkg, safe='/')}@{ver}", "high"
    if re.search(r"-r\d+$", ver):
        return f"pkg:apk/alpine/{pkg}@{ver}", "high"
    if ":" in pkg and "." in pkg.split(":", 1)[0]:
        group, artifact = pkg.split(":", 1)
        if artifact:
            return (
                f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{ver}",
                "high",
            )

    # Medium-confidence fallback via language/ecosystem mapping.
    purl_type = _PURL_TYPE_BY_LANGUAGE.get(lang)
    if not purl_type:
        return None, None
    if purl_type == "maven":
        if ":" in pkg:
            group, artifact = pkg.split(":", 1)
            if artifact:
                return (
                    f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{ver}",
                    "medium",
                )
        return None, None
    if purl_type == "npm":
        return f"pkg:npm/{quote(pkg, safe='/')}@{ver}", "medium"
    if purl_type == "apk":
        return f"pkg:apk/alpine/{pkg}@{ver}", "medium"
    if purl_type == "deb":
        return f"pkg:deb/debian/{pkg}@{ver}", "medium"
    return f"pkg:{purl_type}/{quote(pkg, safe='/')}@{ver}", "medium"


def _purl_from_osv_identity(
    *, name: str, version: str, ecosystem: str
) -> str | None:
    eco = (ecosystem or "").strip()
    pkg = (name or "").strip()
    ver = (version or "").strip()
    if not eco or not pkg or not ver:
        return None
    if eco == "PyPI":
        return f"pkg:pypi/{pkg}@{ver}"
    if eco == "npm":
        return f"pkg:npm/{quote(pkg, safe='/')}@{ver}"
    if eco == "crates.io":
        return f"pkg:cargo/{pkg}@{ver}"
    if eco == "NuGet":
        return f"pkg:nuget/{pkg}@{ver}"
    if eco == "RubyGems":
        return f"pkg:gem/{pkg}@{ver}"
    return None


async def import_sbom(
    db: AsyncSession,
    doc: dict,
    source: str = "manual",
    component: Optional[str] = None,
    finding_tag: Optional[str] = None,
    force_finding_tag_override: bool = False,
    tenant_id: Optional[str] = None,
) -> tuple[int, int]:
    """
    Import CycloneDX SBOM. Dedup by name+version. Merge sources.
    Returns (created, updated) counts.
    """
    packages = _parse_cyclonedx(doc)
    if not packages:
        return 0, 0

    created = 0
    updated = 0
    source_entry = {"name": source, "importedAt": _now()}
    # SBOM-derived per-image tag/digest. Wins over caller-supplied finding_tag,
    # which typically carries a bundle/release tag rather than the artifact tag.
    sbom_tag, sbom_digest = _extract_metadata_tag_digest(doc)

    for pkg in packages:
        comp = pkg.get("component") or component
        comp = _clip(comp, 256)
        pkg_id = _package_id(pkg["name"], pkg["version"], comp)
        license_id = _clip(pkg.get("license_id"), 64)
        risk = license_risk_tier(license_id) if license_id else None

        result = await db.execute(select(SbomPackage).where(SbomPackage.id == pkg_id))
        existing = result.scalar_one_or_none()

        if existing:
            sources = list(existing.sources or [])
            did_update = False
            if not any(s.get("name") == source for s in sources):
                sources.append(source_entry)
                existing.sources = sources
                did_update = True
            if not (existing.purl and str(existing.purl).strip()) and pkg.get("purl"):
                existing.purl = _clip(pkg.get("purl"), 512)
                existing.purl_source = _clip(pkg.get("purl_source"), 32)
                existing.purl_confidence = _clip(pkg.get("purl_confidence"), 16)
                did_update = True
            if did_update:
                # TIMESTAMP WITHOUT TIME ZONE — use naive UTC (asyncpg rejects tz-aware here)
                existing.updated_at = datetime.utcnow()
                updated += 1
        else:
            sp = SbomPackage(
                id=pkg_id,
                name=pkg["name"],
                version=pkg["version"],
                license_id=license_id,
                license_risk=risk,
                component=comp,
                language=pkg.get("language"),
                purl=pkg.get("purl"),
                purl_source=_clip(pkg.get("purl_source"), 32),
                purl_confidence=_clip(pkg.get("purl_confidence"), 16),
                sources=[source_entry],
                tenant_id=tenant_id,
            )
            db.add(sp)
            created += 1

        # Auto-create License finding for Critical/High risk (PRD §5.8.3).
        # Scope by component/asset occurrence so package licenses remain tied to
        # the concrete image/repo where they were observed.
        if risk in ("Critical", "High"):
            from app.services.dedup import make_fingerprint

            cve_id = f"LICENSE-{license_id or 'unknown'}-{pkg['name']}"
            occurrence_scope = f"{pkg['name']}|{comp or ''}"
            fp = make_fingerprint(cve_id, occurrence_scope)
            res = await db.execute(select(Finding).where(Finding.fingerprint_id == fp))
            existing_finding = res.scalar_one_or_none()
            effective_tag = _clip(sbom_tag or finding_tag, 256)
            if existing_finding is None:
                title = f"{license_id} license in {pkg['name']}"
                if comp:
                    title = f"{title} ({comp})"
                finding = Finding(
                    id=f"f-{fp[:8]}",
                    finding_type=FindingType.License,
                    fingerprint_id=fp,
                    cve_id=cve_id,
                    severity=Severity.Critical if risk == "Critical" else Severity.High,
                    status=Status.Open,
                    component=pkg["name"],
                    image=_canonicalize_container_image(comp),
                    tag=effective_tag,
                    image_digest=sbom_digest,
                    title=title[:512],
                    description=(
                        f"SBOM import detected {risk} risk license {license_id}"
                        + (f" in component {comp}" if comp else "")
                    ),
                    source=source,
                    sources=[source_entry],
                    audit=[
                        {
                            "ts": _now(),
                            "user": "system",
                            "action": "License finding from SBOM",
                            "note": None,
                        }
                    ],
                )
                db.add(finding)
            else:
                if effective_tag and (
                    force_finding_tag_override
                    or sbom_tag
                    or not (existing_finding.tag and str(existing_finding.tag).strip())
                ):
                    existing_finding.tag = effective_tag
                if sbom_digest and not (
                    getattr(existing_finding, "image_digest", None)
                    and str(existing_finding.image_digest).strip()
                ):
                    existing_finding.image_digest = sbom_digest

    await db.commit()
    return created, updated


async def import_cyclonedx_sbom_like_ingest(
    db: AsyncSession,
    doc: dict,
    *,
    source: str,
    asset_override: str | None = None,
    tag_override: str | None = None,
    force_tag_override: bool = False,
    source_image_override: str | None = None,
    tenant_id: Optional[str] = None,
) -> tuple[int, int]:
    """
    Import CycloneDX the same way ``POST /api/ingest`` does when the manual source
    parser is ``cyclonedx``: ``extract_sbom_from_report("cyclonedx", …)`` then
    ``import_sbom`` with ``component = source_image_override or asset_override``
    (same as ``X-VAT-Source-Image`` / ``X-VAT-Asset`` from the local scanner).

    Stamps ``vat:container_ref`` on each component when a composite ref is known,
    matching ``vat_scanner.scan._apply_cyclonedx_container_ref`` behavior.
    """
    from app.services.cyclonedx_identity import stamp_vat_container_ref_on_cyclonedx
    from app.services.sbom_extract import extract_sbom_from_report

    sbom_component = (source_image_override or asset_override or "").strip() or None
    stamped = dict(doc) if isinstance(doc, dict) else doc
    if sbom_component:
        stamped = stamp_vat_container_ref_on_cyclonedx(stamped, sbom_component)
    sbom_doc = extract_sbom_from_report("cyclonedx", stamped, source)
    if not sbom_doc:
        return 0, 0
    return await import_sbom(
        db,
        sbom_doc,
        source=source,
        component=sbom_component,
        finding_tag=tag_override,
        force_finding_tag_override=force_tag_override,
        tenant_id=tenant_id,
    )


async def list_sbom_packages(
    db: AsyncSession,
    component: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 500,
) -> list[dict]:
    """List SBOM packages with optional filters.
    When tenant_id is set, includes packages where tenant_id matches OR tenant_id IS NULL (global packages).
    """
    from sqlalchemy import or_

    q = select(SbomPackage)
    if component:
        q = q.where(SbomPackage.component.ilike(f"%{component}%"))
    if tenant_id:
        q = q.where(
            or_(SbomPackage.tenant_id == tenant_id, SbomPackage.tenant_id.is_(None))
        )
    q = q.limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "version": r.version,
            "licenseId": r.license_id,
            "licenseRisk": r.license_risk,
            "component": r.component,
            "language": r.language,
            "purl": r.purl,
            "purlSource": r.purl_source,
            "purlConfidence": r.purl_confidence,
            "sources": r.sources or [],
        }
        for r in rows
    ]


async def backfill_derived_purls(
    db: AsyncSession,
    *,
    only_source: str | None = None,
    limit: int = 0,
) -> dict[str, int]:
    """Populate missing SBOM purls via deterministic derivation rules."""
    q = select(SbomPackage).where(SbomPackage.purl.is_(None))
    if only_source:
        q = q.where(SbomPackage.sources.is_not(None))
    if limit > 0:
        q = q.limit(limit)
    rows = (await db.execute(q)).scalars().all()
    scanned = 0
    updated = 0
    for row in rows:
        scanned += 1
        if only_source:
            sources = row.sources or []
            names = {str(s.get("name") or "").strip().lower() for s in sources if isinstance(s, dict)}
            if only_source.strip().lower() not in names:
                continue
        purl, confidence = _derive_purl(
            name=row.name,
            version=row.version,
            language=row.language,
        )
        if not purl:
            continue
        row.purl = _clip(purl, 512)
        row.purl_source = "derived"
        row.purl_confidence = _clip(confidence, 16)
        row.updated_at = datetime.utcnow()
        updated += 1
    if updated:
        await db.commit()
    return {"scanned": scanned, "updated": updated}


async def backfill_purls_via_osv_probe(
    db: AsyncSession,
    *,
    only_source: str | None = None,
    limit: int = 0,
) -> dict[str, int]:
    """
    Fill missing purls by probing multiple OSV ecosystems and accepting only
    unambiguous (single-ecosystem) vulnerability hits.
    """
    q = select(SbomPackage).where(SbomPackage.purl.is_(None))
    if limit > 0:
        q = q.limit(limit)
    rows = (await db.execute(q)).scalars().all()

    candidate_rows: list[SbomPackage] = []
    for row in rows:
        if only_source:
            sources = row.sources or []
            names = {
                str(s.get("name") or "").strip().lower()
                for s in sources
                if isinstance(s, dict)
            }
            if only_source.strip().lower() not in names:
                continue
        if not (row.name and row.version):
            continue
        # Skip rows where deterministic derivation should be used instead.
        if _derive_purl(name=row.name, version=row.version, language=row.language)[0]:
            continue
        candidate_rows.append(row)

    if not candidate_rows:
        return {"scanned": 0, "updated": 0, "ambiguous": 0, "no_hits": 0}

    ecosystems = ("PyPI", "npm", "crates.io", "NuGet", "RubyGems")
    query_meta: list[tuple[int, str, str, str]] = []
    queries: list[dict] = []
    for idx, row in enumerate(candidate_rows):
        pkg = (row.name or "").strip()
        ver = (row.version or "").strip()
        if not pkg or not ver:
            continue
        for eco in ecosystems:
            query_meta.append((idx, eco, pkg, ver))
            queries.append({"package": {"name": pkg, "ecosystem": eco}, "version": ver})

    if not queries:
        return {"scanned": len(candidate_rows), "updated": 0, "ambiguous": 0, "no_hits": 0}

    settings = get_settings()
    timeout = httpx.Timeout(settings.vuln_feed_request_timeout_sec)
    headers = {"User-Agent": settings.vuln_feed_user_agent}
    by_row_hits: dict[int, set[str]] = {}

    chunk_size = 400
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        for start in range(0, len(queries), chunk_size):
            chunk = queries[start : start + chunk_size]
            chunk_meta = query_meta[start : start + chunk_size]
            resp = await client.post(
                "https://api.osv.dev/v1/querybatch", json={"queries": chunk}
            )
            resp.raise_for_status()
            payload = resp.json()
            results = payload.get("results") if isinstance(payload, dict) else []
            if not isinstance(results, list):
                continue
            for i, row in enumerate(results):
                if i >= len(chunk_meta) or not isinstance(row, dict):
                    continue
                vulns = row.get("vulns")
                if not isinstance(vulns, list) or not vulns:
                    continue
                row_idx, eco, _pkg, _ver = chunk_meta[i]
                by_row_hits.setdefault(row_idx, set()).add(eco)

    updated = 0
    ambiguous = 0
    no_hits = 0
    for idx, row in enumerate(candidate_rows):
        hits = by_row_hits.get(idx, set())
        if not hits:
            no_hits += 1
            continue
        if len(hits) != 1:
            ambiguous += 1
            continue
        eco = next(iter(hits))
        purl = _purl_from_osv_identity(
            name=(row.name or "").strip(),
            version=(row.version or "").strip(),
            ecosystem=eco,
        )
        if not purl:
            continue
        row.purl = _clip(purl, 512)
        row.purl_source = "derived_probe"
        row.purl_confidence = "medium"
        row.updated_at = datetime.utcnow()
        updated += 1

    if updated:
        await db.commit()
    return {
        "scanned": len(candidate_rows),
        "updated": updated,
        "ambiguous": ambiguous,
        "no_hits": no_hits,
    }
