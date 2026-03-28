from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import oauth_clients


@pytest.mark.asyncio
async def test_create_oauth_client_requires_source_id():
    with pytest.raises(ValueError, match="sourceId is required"):
        await oauth_clients.create_oauth_client(SimpleNamespace(), "   ")


@pytest.mark.asyncio
async def test_create_oauth_client_persists_store(monkeypatch):
    saved: dict = {}

    async def fake_get_store(_db):
        return {}

    async def fake_save_store(_db, store):
        saved.update(store)

    monkeypatch.setattr(oauth_clients, "_get_clients_store", fake_get_store)
    monkeypatch.setattr(oauth_clients, "_save_clients_store", fake_save_store)
    monkeypatch.setattr(
        oauth_clients, "generate_client_credentials", lambda: ("vat_oauth_fixed", "secret-1")
    )
    monkeypatch.setattr(oauth_clients, "_now", lambda: "2026-03-21T00:00:00Z")

    client_id, client_secret, msg = await oauth_clients.create_oauth_client(
        SimpleNamespace(), " src-1 "
    )

    assert client_id == "vat_oauth_fixed"
    assert client_secret == "secret-1"
    assert "not be shown again" in msg
    assert saved["src-1"]["clientId"] == "vat_oauth_fixed"
    assert saved["src-1"]["clientSecretHash"] == oauth_clients._hash_secret("secret-1")
    assert saved["src-1"]["createdAt"] == "2026-03-21T00:00:00Z"


@pytest.mark.asyncio
async def test_validate_oauth_client_guards_and_success(monkeypatch):
    store = {
        "src-1": {
            "clientId": "vat_oauth_ok",
            "clientSecretHash": oauth_clients._hash_secret("good-secret"),
        },
        "ignored": "not-a-dict",
    }

    async def fake_get_store(_db):
        return store

    monkeypatch.setattr(oauth_clients, "_get_clients_store", fake_get_store)

    assert await oauth_clients.validate_oauth_client(SimpleNamespace(), "", "x") is None
    assert await oauth_clients.validate_oauth_client(SimpleNamespace(), "x", "") is None
    assert (
        await oauth_clients.validate_oauth_client(
            SimpleNamespace(), "not-prefixed", "good-secret"
        )
        is None
    )
    assert (
        await oauth_clients.validate_oauth_client(
            SimpleNamespace(), "vat_oauth_ok", "wrong-secret"
        )
        is None
    )
    assert await oauth_clients.validate_oauth_client(
        SimpleNamespace(), " vat_oauth_ok ", "good-secret"
    ) == ("src-1", "ingest:src-1")


@pytest.mark.asyncio
async def test_get_client_by_source_paths(monkeypatch):
    async def fake_get_store(_db):
        return {
            "src-1": {
                "clientId": "vat_oauth_1",
                "createdAt": "2026-03-01T00:00:00Z",
                "rotatedAt": "2026-03-02T00:00:00Z",
            },
            "bad": "not-a-dict",
        }

    monkeypatch.setattr(oauth_clients, "_get_clients_store", fake_get_store)

    one = await oauth_clients.get_client_by_source(SimpleNamespace(), "src-1")
    assert one is not None
    assert one.source_id == "src-1"
    assert one.client_id == "vat_oauth_1"
    assert await oauth_clients.get_client_by_source(SimpleNamespace(), "bad") is None
    assert await oauth_clients.get_client_by_source(SimpleNamespace(), "missing") is None


@pytest.mark.asyncio
async def test_rotate_oauth_client_paths(monkeypatch):
    with pytest.raises(ValueError, match="sourceId is required"):
        await oauth_clients.rotate_oauth_client(SimpleNamespace(), "")

    store = {
        "src-1": {
            "clientId": "vat_oauth_keep",
            "clientSecretHash": oauth_clients._hash_secret("old-secret"),
            "createdAt": "2026-03-01T00:00:00Z",
        }
    }
    saved: dict = {}

    async def fake_get_store(_db):
        return store

    async def fake_save_store(_db, s):
        saved.update(s)

    monkeypatch.setattr(oauth_clients, "_get_clients_store", fake_get_store)
    monkeypatch.setattr(oauth_clients, "_save_clients_store", fake_save_store)
    monkeypatch.setattr(
        oauth_clients,
        "generate_client_credentials",
        lambda: ("vat_oauth_unused", "new-secret"),
    )
    monkeypatch.setattr(oauth_clients, "_now", lambda: "2026-03-22T00:00:00Z")

    with pytest.raises(ValueError, match="No OAuth client for source missing"):
        await oauth_clients.rotate_oauth_client(SimpleNamespace(), "missing")

    client_id, client_secret, msg = await oauth_clients.rotate_oauth_client(
        SimpleNamespace(), " src-1 "
    )
    assert client_id == "vat_oauth_keep"
    assert client_secret == "new-secret"
    assert "Previous secret invalidated" in msg
    assert (
        saved["src-1"]["clientSecretHash"] == oauth_clients._hash_secret("new-secret")
    )
    assert saved["src-1"]["rotatedAt"] == "2026-03-22T00:00:00Z"


@pytest.mark.asyncio
async def test_revoke_and_list_oauth_clients(monkeypatch):
    store = {
        "src-1": {"clientId": "vat_oauth_1", "createdAt": "t1"},
        "src-2": {"clientId": "", "createdAt": "t2"},
        "bad": "not-a-dict",
    }
    saved: dict = {}

    async def fake_get_store(_db):
        return store

    async def fake_save_store(_db, s):
        saved.clear()
        saved.update(s)

    monkeypatch.setattr(oauth_clients, "_get_clients_store", fake_get_store)
    monkeypatch.setattr(oauth_clients, "_save_clients_store", fake_save_store)

    listed = await oauth_clients.list_oauth_clients(SimpleNamespace())
    assert [(x.source_id, x.client_id) for x in listed] == [("src-1", "vat_oauth_1")]

    assert await oauth_clients.revoke_oauth_client(SimpleNamespace(), "missing") is False
    assert await oauth_clients.revoke_oauth_client(SimpleNamespace(), "src-1") is True
    assert "src-1" not in saved

