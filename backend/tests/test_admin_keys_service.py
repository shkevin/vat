from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import admin_keys


class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


@pytest.mark.asyncio
async def test_get_store_and_save_store_paths(monkeypatch):
    db = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(SimpleNamespace(value={"ak_1": {"x": 1}}))),
        add=MagicMock(),
        commit=AsyncMock(),
    )

    got = await admin_keys._get_store(db)
    assert got == {"ak_1": {"x": 1}}

    row = SimpleNamespace(value={}, updated_at=None)
    db2 = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(row)),
        add=MagicMock(),
        commit=AsyncMock(),
    )
    monkeypatch.setattr(admin_keys, "_utc_now_naive", lambda: "now-naive")
    await admin_keys._save_store(db2, {"ak_1": {"keyHash": "h"}})
    assert row.value == {"ak_1": {"keyHash": "h"}}
    assert row.updated_at == "now-naive"
    assert db2.add.call_count == 0
    assert db2.commit.await_count == 1

    db3 = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(None)),
        add=MagicMock(),
        commit=AsyncMock(),
    )
    await admin_keys._save_store(db3, {"ak_2": {"keyHash": "h2"}})
    assert db3.add.call_count == 1
    assert db3.commit.await_count == 1

    db4 = SimpleNamespace(
        execute=AsyncMock(return_value=_Result(SimpleNamespace(value="bad"))),
    )
    assert await admin_keys._get_store(db4) == {}


def test_generate_and_internal_helpers(monkeypatch):
    monkeypatch.setattr(admin_keys.secrets, "token_hex", lambda _n: "f" * 64)
    full_key, key_hash, key_prefix = admin_keys.generate_admin_key()
    assert full_key == "vat_" + ("f" * 64)
    assert key_hash == admin_keys._hash_key(full_key)
    assert key_prefix == full_key[: admin_keys.KEY_PREFIX_LEN]
    assert admin_keys._constant_time_compare("a", "a") is True
    assert admin_keys._constant_time_compare("a", "b") is False
    assert admin_keys._next_id({"ak_1": {}, "ak_3": {}, "x": {}}) == "ak_2"


@pytest.mark.asyncio
async def test_create_revoke_list_validate(monkeypatch):
    store = {
        "ak_1": {"keyHash": admin_keys._hash_key("vat_good"), "keyPrefix": "vat_go", "createdAt": "t1"},
        "ak_2": {"keyHash": "", "keyPrefix": "vat_x"},
        "bad": "not-a-dict",
    }
    saved: dict = {}

    async def fake_get_store(_db):
        return dict(store)

    async def fake_save_store(_db, s):
        saved.clear()
        saved.update(s)

    monkeypatch.setattr(admin_keys, "_get_store", fake_get_store)
    monkeypatch.setattr(admin_keys, "_save_store", fake_save_store)
    monkeypatch.setattr(admin_keys, "_now", lambda: "2026-03-21T00:00:00Z")
    monkeypatch.setattr(
        admin_keys,
        "generate_admin_key",
        lambda: ("vat_new", admin_keys._hash_key("vat_new"), "vat_ne"),
    )

    # Cross-tenant key (legacy automation use case).
    key_id, full_key, key_prefix, msg = await admin_keys.create_admin_key(
        SimpleNamespace(), cross_tenant=True
    )
    assert key_id == "ak_3"
    assert full_key == "vat_new"
    assert key_prefix == "vat_ne"
    assert "not be shown again" in msg
    assert saved["ak_3"]["createdAt"] == "2026-03-21T00:00:00Z"
    assert saved["ak_3"]["crossTenant"] is True
    assert saved["ak_3"]["tenantId"] is None

    # create_admin_key requires explicit scope.
    with pytest.raises(ValueError):
        await admin_keys.create_admin_key(SimpleNamespace())
    with pytest.raises(ValueError):
        await admin_keys.create_admin_key(
            SimpleNamespace(), tenant_id="t1", cross_tenant=True
        )

    # Legacy stored entry (no tenantId/crossTenant fields) is treated as
    # cross-tenant for back-compat and surfaced as legacy=True.
    listed = await admin_keys.list_admin_keys(SimpleNamespace())
    assert {(x.id, x.key_prefix, x.cross_tenant, x.legacy) for x in listed} == {
        ("ak_1", "vat_go", True, True)
    }

    assert await admin_keys.validate_admin_key(SimpleNamespace(), "") is False
    assert await admin_keys.validate_admin_key(SimpleNamespace(), "  ") is False
    assert await admin_keys.validate_admin_key(SimpleNamespace(), "bad-prefix") is False
    assert await admin_keys.validate_admin_key(SimpleNamespace(), "vat_wrong") is False
    assert await admin_keys.validate_admin_key(SimpleNamespace(), " vat_good ") is True

    resolved = await admin_keys.resolve_admin_key(SimpleNamespace(), "vat_good")
    assert resolved is not None
    assert resolved.key_id == "ak_1"
    assert resolved.cross_tenant is True
    assert resolved.legacy is True
    assert resolved.tenant_id is None

    assert await admin_keys.revoke_admin_key(SimpleNamespace(), "missing") is False
    assert await admin_keys.revoke_admin_key(SimpleNamespace(), "ak_1") is True
    assert "ak_1" not in saved
