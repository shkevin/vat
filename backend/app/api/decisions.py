"""Decision ledger API — durable waivers and admin backfill."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_context, require_admin, require_reviewer
from app.core.database import get_db
from app.schemas.auth import UserContext
from app.schemas.decision import DecisionBackfillResult, WaiverDecisionRead
from app.services.decision_ledger import (
    backfill_decisions_from_findings,
    list_waiver_decisions,
)

router = APIRouter()


@router.get("/waivers", response_model=list[WaiverDecisionRead])
async def get_waiver_decisions(
    asset_id: Optional[str] = Query(default=None, alias="assetId"),
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_reviewer),
):
    """List durable Risk Accepted decisions (includes unlinked waivers)."""
    rows = await list_waiver_decisions(
        db,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
        asset_id=asset_id,
    )
    return [WaiverDecisionRead.model_validate(row) for row in rows]


@router.post("/backfill", response_model=DecisionBackfillResult)
async def backfill_decisions(
    limit: int = Query(default=5000, ge=1, le=50000),
    db: AsyncSession = Depends(get_db),
    ctx: UserContext = Depends(require_admin),
):
    """Backfill ledger rows from existing findings with triage decisions."""
    result = await backfill_decisions_from_findings(
        db,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
        limit=limit,
    )
    await db.commit()
    return DecisionBackfillResult.model_validate(result)
