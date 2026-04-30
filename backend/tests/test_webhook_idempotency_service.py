from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services import webhook_idempotency


class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


def test_compute_idempotency_key_is_stable_and_64():
    k1 = webhook_idempotency.compute_idempotency_key("linear", "Issue", "a", None, "b")
    k2 = webhook_idempotency.compute_idempotency_key("linear", "Issue", "a", "b")
    assert len(k1) == 64
    assert k1 == k2
    assert k1 != webhook_idempotency.compute_idempotency_key("linear", "Issue", "a", "c")


def test_payload_hash_normalizes_key_order():
    h1 = webhook_idempotency._payload_hash({"a": 1, "z": 9})
    h2 = webhook_idempotency._payload_hash({"z": 9, "a": 1})
    assert h1 == h2
    assert webhook_idempotency._payload_hash(None) is None


@pytest.mark.asyncio
async def test_is_duplicate_webhook():
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result(None)))
    assert await webhook_idempotency.is_duplicate_webhook(db, "k1") is False

    db2 = SimpleNamespace(execute=AsyncMock(return_value=_Result(object())))
    assert await webhook_idempotency.is_duplicate_webhook(db2, "k1") is True


@pytest.mark.asyncio
async def test_claim_webhook_returns_true_on_first_insert():
    """ON CONFLICT DO NOTHING RETURNING id returns the new row's id when this
    caller wins the race."""
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result("uuid-1")))
    claimed = await webhook_idempotency.claim_webhook(
        db, "idem-1", "linear", "IssueUpdated", {"a": 1}, {"ok": True}
    )
    assert claimed is True
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_claim_webhook_returns_false_on_conflict():
    """When another writer already inserted the key, returning() yields no
    row and the caller must skip the side effect."""
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result(None)))
    claimed = await webhook_idempotency.claim_webhook(db, "idem-1", "linear")
    assert claimed is False


@pytest.mark.asyncio
async def test_record_webhook_processed_executes_insert():
    db = SimpleNamespace(execute=AsyncMock())
    await webhook_idempotency.record_webhook_processed(
        db, "idem-1", "linear", "IssueUpdated", {"a": 1}, {"ok": True}
    )
    db.execute.assert_awaited_once()
