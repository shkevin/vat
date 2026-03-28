from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.webhook_event import WebhookEvent
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


@pytest.mark.asyncio
async def test_is_duplicate_webhook():
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result(None)))
    assert await webhook_idempotency.is_duplicate_webhook(db, "k1") is False

    db2 = SimpleNamespace(execute=AsyncMock(return_value=_Result(object())))
    assert await webhook_idempotency.is_duplicate_webhook(db2, "k1") is True


@pytest.mark.asyncio
async def test_record_webhook_processed_with_and_without_payload():
    db = SimpleNamespace(add=MagicMock())
    await webhook_idempotency.record_webhook_processed(
        db,
        "idem-1",
        "linear",
        "IssueUpdated",
        {"z": 1, "a": 2},
        {"ok": True},
    )
    added = db.add.call_args.args[0]
    assert isinstance(added, WebhookEvent)
    assert added.idempotency_key == "idem-1"
    assert added.source == "linear"
    assert added.event_type == "IssueUpdated"
    assert added.payload_hash is not None
    assert added.result == {"ok": True}

    db2 = SimpleNamespace(add=MagicMock())
    await webhook_idempotency.record_webhook_processed(
        db2, "idem-2", "linear", "IssueUpdated", None, None
    )
    added2 = db2.add.call_args.args[0]
    assert added2.payload_hash is None
