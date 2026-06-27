"""Unit tests for asset alias helper service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import asset_aliases


@pytest.fixture(autouse=True)
def _no_ledger_alias(monkeypatch):
    """These unit tests mock the DB; the asset-merge ledger hook is tested separately."""
    monkeypatch.setattr(
        "app.services.decision_ledger.register_decision_aliases_for_asset_merge",
        AsyncMock(return_value=0),
    )


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)


@pytest.mark.asyncio
async def test_resolve_canonical_asset_id_handles_empty_and_missing():
    db = SimpleNamespace(get=AsyncMock(return_value=None))
    assert await asset_aliases.resolve_canonical_asset_id(db, "   ") == ""
    assert await asset_aliases.resolve_canonical_asset_id(db, "a") == "a"


@pytest.mark.asyncio
async def test_resolve_canonical_asset_id_chain_loop_and_depth():
    mapping = {
        "a": SimpleNamespace(canonical_asset_id="b"),
        "b": SimpleNamespace(canonical_asset_id="c"),
        "c": SimpleNamespace(canonical_asset_id="c"),
    }

    async def _get(_model, key):
        return mapping.get(key)

    db = SimpleNamespace(get=AsyncMock(side_effect=_get))
    assert await asset_aliases.resolve_canonical_asset_id(db, "a") == "c"

    loop_map = {
        "x": SimpleNamespace(canonical_asset_id="y"),
        "y": SimpleNamespace(canonical_asset_id="x"),
    }
    db_loop = SimpleNamespace(get=AsyncMock(side_effect=lambda _m, k: loop_map.get(k)))
    # Loop halts safely and returns current pointer.
    assert await asset_aliases.resolve_canonical_asset_id(db_loop, "x") == "x"

    deep_map = {"m": SimpleNamespace(canonical_asset_id="n"), "n": SimpleNamespace(canonical_asset_id="o")}
    db_deep = SimpleNamespace(get=AsyncMock(side_effect=lambda _m, k: deep_map.get(k)))
    assert await asset_aliases.resolve_canonical_asset_id(db_deep, "m", max_depth=1) == "n"


@pytest.mark.asyncio
async def test_upsert_asset_alias_validates_and_updates_existing():
    db = SimpleNamespace(get=AsyncMock(return_value=None), add=MagicMock())

    with pytest.raises(ValueError):
        await asset_aliases.upsert_asset_alias(db, source_asset_id="", canonical_asset_id="x")
    with pytest.raises(ValueError):
        await asset_aliases.upsert_asset_alias(db, source_asset_id="same", canonical_asset_id="same")

    row = await asset_aliases.upsert_asset_alias(
        db,
        source_asset_id="source",
        canonical_asset_id="target",
        created_by="admin@vat.local",
    )
    assert row.source_asset_id == "source"
    assert row.canonical_asset_id == "target"
    assert row.created_by == "admin@vat.local"
    assert db.add.call_count == 1

    existing = SimpleNamespace(source_asset_id="source", canonical_asset_id="old", created_by=None)
    db2 = SimpleNamespace(get=AsyncMock(return_value=existing), add=MagicMock())
    out = await asset_aliases.upsert_asset_alias(
        db2,
        source_asset_id="source",
        canonical_asset_id="new",
        created_by="who",
    )
    assert out is existing
    assert existing.canonical_asset_id == "new"
    assert existing.created_by == "who"
    assert db2.add.call_count == 0


@pytest.mark.asyncio
async def test_repoint_aliases_and_record_merge_event():
    rows = [
        SimpleNamespace(source_asset_id="a", canonical_asset_id="old"),
        SimpleNamespace(source_asset_id="new", canonical_asset_id="old"),
    ]
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result(rows)), add=MagicMock())

    assert await asset_aliases.repoint_aliases(db, old_canonical_id="", new_canonical_id="new") == 0
    changed = await asset_aliases.repoint_aliases(
        db, old_canonical_id="old", new_canonical_id="new"
    )
    assert changed == 1
    assert rows[0].canonical_asset_id == "new"
    assert rows[1].canonical_asset_id == "old"  # skipped self-loop guard

    event = await asset_aliases.record_merge_event(
        db,
        source_asset_id=" s ",
        target_asset_id=" t ",
        finding_id="f1",
        prev_values={},
        next_values={},
        created_by="user@test",
    )
    assert event.source_asset_id == "s"
    assert event.target_asset_id == "t"
    assert event.finding_id == "f1"
    assert event.created_by == "user@test"
    assert db.add.call_count >= 1
