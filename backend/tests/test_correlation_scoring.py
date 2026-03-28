"""Tests for correlation score/tier policy."""

from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.services.correlation_scoring import score_finding_pair
from app.services.crosswalks import ingest_crosswalk_entries
from app.services.finding_identifiers import upsert_identifier_facts_for_finding


def _finding(**kwargs):
    base = dict(
        id="f-1",
        image="repo/app",
        branch="main",
        tag="v1",
        component="repo/app",
        cve_id="CVE-2026-0001",
        correlation_key="v1:sca:repo/app:main:v1:npm:openssl:cve-2026-0001",
        rule_id=None,
        stable_rule_key=None,
        benchmark_family=None,
        control_ref=None,
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_score_high_on_same_asset_and_same_key(db):
    left = _finding(id="f-a")
    right = _finding(id="f-b")
    decision = await score_finding_pair(db, left, right)
    assert decision["tier"] == "high"
    assert decision["score"] >= 0.85


@pytest.mark.asyncio
async def test_score_low_on_asset_mismatch(db):
    left = _finding(id="f-a", image="repo/a")
    right = _finding(id="f-b", image="repo/b")
    decision = await score_finding_pair(db, left, right)
    assert decision["tier"] == "low"
    assert decision["score"] == 0.0


@pytest.mark.asyncio
async def test_score_uses_crosswalk_bridge(db):
    await ingest_crosswalk_entries(
        db,
        source="unit",
        source_version="v1",
        entries=[
            {
                "from_namespace": "rule_id",
                "from_value": "SV-1111",
                "to_namespace": "stable_rule_key",
                "to_value": "V-1111",
            }
        ],
    )
    await db.commit()

    left = _finding(
        id="f-a",
        correlation_key="custom:key",
        cve_id="",
        rule_id="SV-1111",
        stable_rule_key=None,
    )
    right = _finding(
        id="f-b",
        correlation_key="different:key",
        cve_id="",
        rule_id=None,
        stable_rule_key="V-1111",
    )
    decision = await score_finding_pair(db, left, right)
    assert "crosswalk_bridge" in decision["reasons"]
    assert decision["score"] > 0


@pytest.mark.asyncio
async def test_score_uses_identifier_facts_when_inline_fields_missing(db):
    try:
        await db.execute(text("SELECT 1 FROM finding_identifiers LIMIT 1"))
    except Exception as exc:
        pytest.skip(f"finding_identifiers table unavailable: {exc}")

    left = _finding(
        id="f-a",
        cve_id="",
        rule_id=None,
        stable_rule_key=None,
        correlation_key="left:key",
    )
    right = _finding(
        id="f-b",
        cve_id="",
        rule_id=None,
        stable_rule_key=None,
        correlation_key="right:key",
    )
    await upsert_identifier_facts_for_finding(
        db,
        finding=SimpleNamespace(id="f-a", cve_id="CVE-2026-3333"),
        source="unit",
    )
    await upsert_identifier_facts_for_finding(
        db,
        finding=SimpleNamespace(id="f-b", cve_id="CVE-2026-3333"),
        source="unit",
    )
    await db.commit()
    decision = await score_finding_pair(db, left, right)
    assert decision["score"] >= 0.1
    assert "shared_identifier_fact" in decision["reasons"]

