"""VAT data API — findings + assets in one response."""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.schemas.finding import FindingRead
from app.services.assets_service import get_assets_with_findings
from app.services.findings_service import (
    enrich_findings_with_source_group_severity,
    list_findings,
)
from app.services.grouping import get_finding_group_key

router = APIRouter()


@router.get("")
async def get_vat_data(
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(get_current_user_context),
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    type: Optional[str] = None,
    asset: Optional[str] = None,
    search: Optional[str] = None,
    search_fields: Optional[str] = None,
    limit: int = 0,
):
    """
    Return findings and assets in one response.
    Assets include integration-created records (e.g. Aikido repos with 0 findings).
    """
    findings = await list_findings(
        db,
        tenant_id=ctx.tenant_id,
        archived=archived,
        status=status,
        severity=severity,
        source=source,
        finding_type=type,
        asset=asset,
        search=search,
        search_fields=search_fields,
        limit=limit,
    )
    rows = [FindingRead.model_validate(f).to_api_dict() for f in findings]
    for i, f in enumerate(findings):
        rows[i]["groupKey"] = get_finding_group_key(f)
    rows = await enrich_findings_with_source_group_severity(db, rows)

    assets = await get_assets_with_findings(db, findings_dicts=rows)
    return {"findings": rows, "assets": assets}
