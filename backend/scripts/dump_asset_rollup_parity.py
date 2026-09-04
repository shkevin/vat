#!/usr/bin/env -S uv run python
"""Dump both sides of the asset-rollup parity check.

Run against a database with real data, then compare with the frontend's
reference implementation:

    kubectl -n vat exec <backend-pod> -- sh -c \
      'cd /app && PYTHONPATH=/app .venv/bin/python scripts/dump_asset_rollup_parity.py /tmp/parity.json'
    kubectl -n vat cp vat/<backend-pod>:/tmp/parity.json frontend/lib/__parity.json
    cd frontend && npx vitest run lib/assetRollupParity.test.ts

The comparison skips itself when the dump is absent, so it is safe in CI.
Delete __parity.json afterwards — it contains real asset names.


backend[] = what get_assets_with_findings computes today.
findings[] = the minimal projection deriveAssets needs, so the frontend
reference implementation can be run over the identical input.
"""
import asyncio, json, sys
from app.core.database import async_session
from app.services.findings_service import stream_findings
from app.services.grouping import finding_to_api_dict_with_group_key
from app.services.assets_service import get_assets_with_findings

KEEP = ("id","status","severity","slaDue","image","component","tag",
        "sourceGroupSeverity","findingType","source","archived")

async def main():
    rows = []
    async with async_session() as s:
        async for batch in stream_findings(s, limit=0, slim=True, batch_size=2000):
            rows.extend(finding_to_api_dict_with_group_key(f, slim=True) for f in batch)
        assets = await get_assets_with_findings(
            s, findings_dicts=rows, include_zero_assets=False,
            include_findings=False, include_finding_derived_assets=True,
        )
    slim = [{k: r.get(k) for k in KEEP} for r in rows]
    backend = [{k: a.get(k) for k in
                ("id","type","tag","worstSeverity","openCount","inReviewCount",
                 "overdueCount","verifiedPct","oraPct","statusBreakdown")} for a in assets]
    json.dump({"findings": slim, "backend": backend}, open(sys.argv[1], "w"), default=str)
    print(f"findings={len(slim)} backendAssets={len(backend)}")
asyncio.run(main())
