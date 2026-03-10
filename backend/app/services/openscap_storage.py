"""OpenSCAP scan result storage — persist raw XCCDF/OVAL XML for STIG Viewer export."""

import logging
from typing import Optional

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.openscap_scan_result import OpenSCAPScanResult

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
            raw_xccdf_xml=raw_xml,
            benchmark_id=benchmark_id,
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
    return list(result.scalars().all())
