from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import ingest_keys


def test_generate_key_and_hash_helpers(monkeypatch):
    monkeypatch.setattr(ingest_keys.secrets, "token_hex", lambda _n: "a" * 64)
    full_key, key_hash, key_prefix = ingest_keys.generate_key()
    assert full_key.startswith("vat_")
    assert full_key == "vat_" + ("a" * 64)
    assert key_hash == ingest_keys._hash_key(full_key)
    assert key_prefix == full_key[: ingest_keys.KEY_PREFIX_LEN]
    assert ingest_keys._constant_time_compare("x", "x") is True
    assert ingest_keys._constant_time_compare("x", "y") is False


@pytest.mark.asyncio
async def test_create_key_requires_source_id():
    with pytest.raises(ValueError, match="sourceId is required"):
        await ingest_keys.create_key(SimpleNamespace(), "   ")


@pytest.mark.asyncio
async def test_create_key_persists_trimmed_source(monkeypatch):
    saved: dict = {}

    async def fake_get_store(_db):
        return {}

    async def fake_save_store(_db, store):
        saved.update(store)

    monkeypatch.setattr(ingest_keys, "_get_keys_store", fake_get_store)
    monkeypatch.setattr(ingest_keys, "_save_keys_store", fake_save_store)
    monkeypatch.setattr(
        ingest_keys, "generate_key", lambda: ("vat_k1", ingest_keys._hash_key("vat_k1"), "vat_k1")
    )
    monkeypatch.setattr(ingest_keys, "_now", lambda: "2026-03-21T00:00:00Z")

    full_key, key_prefix, msg = await ingest_keys.create_key(SimpleNamespace(), " src-1 ")
    assert full_key == "vat_k1"
    assert key_prefix == "vat_k1"
    assert "not be shown again" in msg
    assert saved["src-1"]["sourceId"] == "src-1"
    assert saved["src-1"]["authType"] == "api_token"
    assert saved["src-1"]["createdAt"] == "2026-03-21T00:00:00Z"


@pytest.mark.asyncio
async def test_regenerate_key_existing_and_new_source(monkeypatch):
    store = {
        "src-1": {
            "authType": "api_token",
            "keyHash": "old",
            "keyPrefix": "vat_old",
            "createdAt": "2026-03-01T00:00:00Z",
            "sourceId": "src-1",
        }
    }
    saved: dict = {}
    key_index = {"n": 0}

    async def fake_get_store(_db):
        return store

    async def fake_save_store(_db, s):
        saved.clear()
        saved.update(s)

    def fake_generate():
        key_index["n"] += 1
        key = f"vat_new_{key_index['n']}"
        return key, ingest_keys._hash_key(key), key[: ingest_keys.KEY_PREFIX_LEN]

    monkeypatch.setattr(ingest_keys, "_get_keys_store", fake_get_store)
    monkeypatch.setattr(ingest_keys, "_save_keys_store", fake_save_store)
    monkeypatch.setattr(ingest_keys, "generate_key", fake_generate)
    monkeypatch.setattr(ingest_keys, "_now", lambda: "2026-03-22T00:00:00Z")

    full_key, prefix, msg = await ingest_keys.regenerate_key(SimpleNamespace(), "src-1")
    assert full_key == "vat_new_1"
    assert prefix == "vat_ne"
    assert "invalidated" in msg
    assert saved["src-1"]["createdAt"] == "2026-03-01T00:00:00Z"
    assert saved["src-1"]["rotatedAt"] == "2026-03-22T00:00:00Z"

    full_key2, prefix2, _ = await ingest_keys.regenerate_key(SimpleNamespace(), "src-2")
    assert full_key2 == "vat_new_2"
    assert prefix2 == "vat_ne"
    assert saved["src-2"]["sourceId"] == "src-2"
    assert saved["src-2"]["createdAt"] == "2026-03-22T00:00:00Z"
    assert saved["src-2"]["rotatedAt"] == "2026-03-22T00:00:00Z"


@pytest.mark.asyncio
async def test_revoke_list_and_validate(monkeypatch):
    store = {
        "src-1": {
            "authType": "api_token",
            "keyHash": ingest_keys._hash_key("vat_good"),
            "keyPrefix": "vat_go",
            "createdAt": "t1",
            "rotatedAt": "t2",
        },
        "src-2": {"authType": "api_token", "keyHash": "", "keyPrefix": "vat_x"},
        "bad": "not-a-dict",
    }
    saved: dict = {}

    async def fake_get_store(_db):
        return store

    async def fake_save_store(_db, s):
        saved.clear()
        saved.update(s)

    monkeypatch.setattr(ingest_keys, "_get_keys_store", fake_get_store)
    monkeypatch.setattr(ingest_keys, "_save_keys_store", fake_save_store)

    listed = await ingest_keys.list_keys(SimpleNamespace())
    assert [(x.source_id, x.key_prefix, x.configured) for x in listed] == [
        ("src-1", "vat_go", True)
    ]

    assert await ingest_keys.validate_key(SimpleNamespace(), "") is None
    assert await ingest_keys.validate_key(SimpleNamespace(), "  ") is None
    assert await ingest_keys.validate_key(SimpleNamespace(), "bad-prefix") is None
    assert await ingest_keys.validate_key(SimpleNamespace(), "vat_wrong") is None
    assert await ingest_keys.validate_key(SimpleNamespace(), " vat_good ") == (
        "src-1",
        "ingest:src-1",
    )

    assert await ingest_keys.revoke_key(SimpleNamespace(), "missing") is False
    assert await ingest_keys.revoke_key(SimpleNamespace(), "src-1") is True
    assert "src-1" not in saved
