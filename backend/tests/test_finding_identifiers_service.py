from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app.models.finding_identifier import FindingIdentifier
from app.services.finding_identifiers import (
    list_identifier_facts_for_finding,
    upsert_identifier_facts_for_finding,
)


async def _ensure_table(db) -> None:
    try:
        await db.execute(text("SELECT 1 FROM finding_identifiers LIMIT 1"))
    except Exception as exc:
        pytest.skip(f"finding_identifiers table unavailable: {exc}")


@pytest.mark.asyncio
async def test_upsert_identifier_facts_for_finding(db):
    await _ensure_table(db)
    finding = SimpleNamespace(
        id="fact-1",
        cve_id="CVE-2026-1111",
        rule_id="SV-1234",
        stable_rule_key="V-1234",
        benchmark_family="RHEL_9_STIG",
        control_ref="CCI-000001",
        ecosystem="rpm",
    )
    await upsert_identifier_facts_for_finding(db, finding=finding, source="unit")
    await db.commit()
    rows = (
        await db.execute(
            select(FindingIdentifier).where(FindingIdentifier.finding_id == "fact-1")
        )
    ).scalars().all()
    pairs = {(r.namespace, r.value) for r in rows}
    assert ("cve_id", "cve-2026-1111") in pairs
    assert ("stable_rule_key", "v-1234") in pairs
    assert ("control_ref", "cci-000001") in pairs


@pytest.mark.asyncio
async def test_list_identifier_facts_for_finding(db):
    await _ensure_table(db)
    finding = SimpleNamespace(id="fact-2", cve_id="CVE-2026-2222")
    await upsert_identifier_facts_for_finding(db, finding=finding, source="unit")
    await db.commit()
    pairs = await list_identifier_facts_for_finding(db, finding_id="fact-2")
    assert ("cve_id", "cve-2026-2222") in pairs

