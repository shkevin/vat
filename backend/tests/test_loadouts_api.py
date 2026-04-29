"""Asset loadouts API: ownership/sharing semantics + bulk-add idempotency.

Pure-unit shape via TestClient — these run without integration DB
because we use SQLAlchemy models against the test session fixture
provided by conftest. The cross-tenant + sharing matrix is the part
worth locking in.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text


@pytest.fixture
async def _loadouts_clean(db):
    await db.execute(text("DELETE FROM asset_loadouts"))
    await db.commit()
    yield
    await db.execute(text("DELETE FROM asset_loadouts"))
    await db.commit()


@pytest.mark.anyio
async def test_create_then_list_returns_owners_loadout(client, _loadouts_clean) -> None:
    payload = {
        "name": "Test loadout",
        "asset_ids": ["containers/images/foo", "containers/images/bar"],
        "shared_with_team": False,
    }
    resp = await client.post("/api/loadouts", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "Test loadout"
    assert body["asset_ids"] == ["containers/images/foo", "containers/images/bar"]
    assert body["is_owner"] is True

    listed = (await client.get("/api/loadouts")).json()
    assert listed["count"] >= 1
    assert any(l["id"] == body["id"] for l in listed["loadouts"])


@pytest.mark.anyio
async def test_create_dedupes_asset_ids(client, _loadouts_clean) -> None:
    resp = await client.post(
        "/api/loadouts",
        json={"name": "dup", "asset_ids": ["a", "b", "a", "c", "b"]},
    )
    assert resp.json()["asset_ids"] == ["a", "b", "c"]


@pytest.mark.anyio
async def test_add_items_idempotent_dedupes_against_existing(
    client, _loadouts_clean
) -> None:
    created = (
        await client.post(
            "/api/loadouts", json={"name": "x", "asset_ids": ["a", "b"]}
        )
    ).json()
    resp = await client.post(
        f"/api/loadouts/{created['id']}/items",
        json={"asset_ids": ["b", "c", "a", "d"]},
    )
    assert resp.status_code == 200
    assert resp.json()["asset_ids"] == ["a", "b", "c", "d"]


@pytest.mark.anyio
async def test_update_replaces_asset_ids(client, _loadouts_clean) -> None:
    created = (
        await client.post(
            "/api/loadouts", json={"name": "x", "asset_ids": ["a", "b"]}
        )
    ).json()
    resp = await client.put(
        f"/api/loadouts/{created['id']}",
        json={"asset_ids": ["x", "y"]},
    )
    assert resp.status_code == 200
    assert resp.json()["asset_ids"] == ["x", "y"]


@pytest.mark.anyio
async def test_delete_removes_loadout(client, _loadouts_clean) -> None:
    created = (
        await client.post("/api/loadouts", json={"name": "to-delete"})
    ).json()
    assert (
        await client.delete(f"/api/loadouts/{created['id']}")
    ).status_code == 200
    assert (
        await client.get(f"/api/loadouts/{created['id']}")
    ).status_code == 404


@pytest.mark.anyio
async def test_bulk_delete_handles_missing_ids(client, db) -> None:
    """Bulk-delete returns per-id status — present + missing + duplicates."""
    from app.models.asset import Asset

    db.add(Asset(id="bd-test-real", name="bd-test-real", type="package", source="test"))
    await db.commit()
    resp = await client.post(
        "/api/assets/bulk-delete",
        json={"asset_ids": ["bd-test-real", "bd-does-not-exist", "bd-test-real"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted"] == 1
    assert body["not_found"] == 1
    by_id = {r["asset_id"]: r for r in body["results"]}
    assert by_id["bd-test-real"]["status"] == "deleted"
    assert by_id["bd-does-not-exist"]["status"] == "not_found"
