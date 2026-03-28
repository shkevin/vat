"""SBOM service — CycloneDX import, dedup by name+version. PRD §5.8."""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingType, Severity, Status
from app.models.sbom import SbomPackage, license_risk_tier


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
        name = c.get("name") or c.get("purl", "").split("/")[-1] or "unknown"
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

        out.append(
            {
                "name": name,
                "version": version,
                "license_id": license_id,
                "component": str(component) if component else None,
                "language": str(language) if language else None,
            }
        )
    return out


async def import_sbom(
    db: AsyncSession,
    doc: dict,
    source: str = "manual",
    component: Optional[str] = None,
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
            if not any(s.get("name") == source for s in sources):
                sources.append(source_entry)
                existing.sources = sources
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
                res = await db.execute(
                    select(Finding).where(Finding.fingerprint_id == fp)
                )
                if res.scalar_one_or_none() is None:
                    title = f"{license_id} license in {pkg['name']}"
                    if comp:
                        title = f"{title} ({comp})"
                    finding = Finding(
                        id=f"f-{fp[:8]}",
                        finding_type=FindingType.License,
                        fingerprint_id=fp,
                        cve_id=cve_id,
                        severity=Severity.Critical
                        if risk == "Critical"
                        else Severity.High,
                        status=Status.Open,
                        component=pkg["name"],
                        image=comp,
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

    await db.commit()
    return created, updated


async def import_cyclonedx_sbom_like_ingest(
    db: AsyncSession,
    doc: dict,
    *,
    source: str,
    asset_override: str | None = None,
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
        db, sbom_doc, source=source, component=sbom_component, tenant_id=tenant_id
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
            "sources": r.sources or [],
        }
        for r in rows
    ]
