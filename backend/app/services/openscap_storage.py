"""OpenSCAP scan result storage — persist raw XCCDF/OVAL XML for STIG Viewer export."""

import hashlib
import logging
from typing import Optional

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.openscap_evidence_blob import OpenSCAPEvidenceBlob
from app.models.openscap_scan_result import OpenSCAPScanResult
from app.services.openscap_identity import (
    extract_content_version,
    normalize_benchmark_family,
    normalize_profile_scope,
)

logger = logging.getLogger(__name__)


def _extract_benchmark_id_from_xml(raw: bytes) -> Optional[str]:
    """Extract benchmark id from XCCDF/OVAL XML if present."""
    try:
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw)
        tag = root.tag or ""
        if "Benchmark" in tag:
            return root.get("id")
        if "oval_results" in tag.lower():
            return "oval_results"
    except Exception:
        pass
    return None


def compute_evidence_sha256(raw_xml: bytes) -> str:
    """Compute content-addressed hash for raw evidence."""
    return hashlib.sha256(raw_xml or b"").hexdigest()


def _extract_profile_scope_from_xml(raw: bytes) -> Optional[str]:
    """Extract XCCDF TestResult profile scope when present."""
    try:
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw)
        for ns in (
            "{http://checklists.nist.gov/xccdf/1.1}",
            "{http://checklists.nist.gov/xccdf/1.2}",
        ):
            tr = root.find(f".//{ns}TestResult")
            if tr is None:
                continue
            profile = (tr.get("profile") or "").strip()
            if profile:
                return normalize_profile_scope(profile)
    except Exception:
        pass
    return None


async def store_openscap_scan_result(
    db: AsyncSession,
    raw_xml: bytes,
    parser_id: str,
    source_id: str,
    asset_id: str,
    tenant_id: Optional[str] = None,
) -> None:
    """
    Store raw OpenSCAP XCCDF/OVAL XML for STIG Viewer export.
    Upserts by (asset_id, source_id) so re-scans overwrite.
    """
    if not raw_xml or len(raw_xml) == 0:
        return
    benchmark_id = _extract_benchmark_id_from_xml(raw_xml)
    benchmark_family, needs_family_classification = normalize_benchmark_family(
        benchmark_id
    )
    content_version = extract_content_version(benchmark_id)
    profile_scope = _extract_profile_scope_from_xml(raw_xml)
    evidence_sha = compute_evidence_sha256(raw_xml)

    # Upsert deduplicated blob by content hash.
    blob = await db.get(OpenSCAPEvidenceBlob, evidence_sha)
    if blob is None:
        db.add(
            OpenSCAPEvidenceBlob(
                sha256=evidence_sha,
                raw_xml=raw_xml,
                size_bytes=len(raw_xml),
            )
        )

    await db.execute(
        delete(OpenSCAPScanResult).where(
            OpenSCAPScanResult.asset_id == asset_id,
            OpenSCAPScanResult.source_id == source_id,
        )
    )
    db.add(
        OpenSCAPScanResult(
            asset_id=asset_id,
            source_id=source_id,
            raw_xccdf_xml=None,
            evidence_sha256=evidence_sha,
            benchmark_id=benchmark_id,
            benchmark_family=benchmark_family,
            content_version=content_version,
            profile_scope=profile_scope,
            needs_family_classification=needs_family_classification,
            parser_id=parser_id,
            tenant_id=tenant_id,
        )
    )
    await db.commit()
    logger.debug("Stored OpenSCAP scan result: asset=%s source=%s", asset_id, source_id)


async def list_openscap_scan_results(
    db: AsyncSession,
    tenant_id: Optional[str] = None,
) -> list[OpenSCAPScanResult]:
    """List OpenSCAP scan results for export. When tenant_id set, includes tenant + global (NULL) results."""
    q = select(OpenSCAPScanResult).order_by(OpenSCAPScanResult.asset_id)
    if tenant_id:
        q = q.where(
            or_(
                OpenSCAPScanResult.tenant_id == tenant_id,
                OpenSCAPScanResult.tenant_id.is_(None),
            )
        )
    result = await db.execute(q)
    rows = list(result.scalars().all())

    # Hydrate raw XML from content-addressed blob when needed (export compatibility).
    needed = [
        r.evidence_sha256 for r in rows if r.raw_xccdf_xml is None and r.evidence_sha256
    ]
    if needed:
        blob_result = await db.execute(
            select(OpenSCAPEvidenceBlob).where(OpenSCAPEvidenceBlob.sha256.in_(needed))
        )
        blob_by_sha = {b.sha256: b for b in blob_result.scalars().all()}
        for row in rows:
            if row.raw_xccdf_xml is not None or not row.evidence_sha256:
                continue
            blob = blob_by_sha.get(row.evidence_sha256)
            if blob is not None:
                row.raw_xccdf_xml = blob.raw_xml

    return rows
