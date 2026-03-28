"""Tests for crosswalk ingestion and resolution service."""

import pytest

from app.services.crosswalks import (
    identifiers_crosswalk_match,
    ingest_crosswalk_entries,
    resolve_crosswalk_values,
)


@pytest.mark.asyncio
async def test_ingest_and_resolve_crosswalk_entries(db):
    run = await ingest_crosswalk_entries(
        db,
        source="test-source",
        source_version="v1",
        entries=[
            {
                "from_namespace": "rule_id",
                "from_value": "SV-1234",
                "to_namespace": "stable_rule_key",
                "to_value": "V-1234",
                "confidence": "high",
                "score": 0.95,
                "metadata": {"kind": "unit"},
            }
        ],
        created_by="tester",
    )
    await db.commit()
    assert run.status == "completed"
    assert (run.stats["inserted"] + run.stats["updated"]) >= 1

    rows = await resolve_crosswalk_values(
        db,
        from_namespace="rule_id",
        from_value="SV-1234",
        to_namespace="stable_rule_key",
    )
    assert len(rows) >= 1
    assert rows[0].to_value == "v-1234"
    assert rows[0].source == "test-source"


@pytest.mark.asyncio
async def test_identifiers_crosswalk_match(db):
    await ingest_crosswalk_entries(
        db,
        source="test-source",
        source_version="v1",
        entries=[
            {
                "from_namespace": "rule_id",
                "from_value": "SV-7777",
                "to_namespace": "stable_rule_key",
                "to_value": "V-7777",
                "confidence": "medium",
            }
        ],
        created_by="tester",
    )
    await db.commit()

    matches = await identifiers_crosswalk_match(
        db,
        left=[("rule_id", "SV-7777")],
        right=[("stable_rule_key", "V-7777")],
    )
    assert len(matches) == 1
    assert matches[0]["from_namespace"] == "rule_id"
    assert matches[0]["to_namespace"] == "stable_rule_key"

