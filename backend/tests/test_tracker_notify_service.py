from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.finding import Status
from app.services import tracker_notify


@pytest.mark.asyncio
async def test_notify_tracker_decision_db_tracker_key_and_no_api_key(monkeypatch):
    finding = SimpleNamespace(
        id="f1",
        status=Status.Approved,
        reviewer_note=None,
        justification=None,
        attestation=None,
    )
    monkeypatch.setattr(
        "app.api.settings.get_tracker_key", AsyncMock(return_value="linear")
    )
    monkeypatch.setattr(
        "app.services.external_links_service.get_tracker_issue_id",
        lambda _finding, _tracker_key: "VAT-22",
    )

    monkeypatch.setattr(
        tracker_notify, "get_settings", lambda: SimpleNamespace(linear_api_key="")
    )
    out = await tracker_notify.notify_tracker_decision(
        finding, user="u@test", db=SimpleNamespace()
    )
    assert out is False


@pytest.mark.asyncio
async def test_notify_tracker_decision_exception_path(monkeypatch):
    finding = SimpleNamespace(
        id="f2",
        status=Status.Approved,
        reviewer_note="n",
        justification="j",
        attestation=None,
    )
    monkeypatch.setattr(
        "app.services.external_links_service.get_tracker_issue_id",
        lambda _finding, _tracker_key: "VAT-99",
    )
    monkeypatch.setattr(
        tracker_notify, "get_settings", lambda: SimpleNamespace(linear_api_key="x")
    )
    monkeypatch.setattr(tracker_notify, "LinearAdapter", lambda: SimpleNamespace())
    monkeypatch.setattr(
        tracker_notify,
        "retry_async",
        AsyncMock(side_effect=RuntimeError("post failed")),
    )

    out = await tracker_notify.notify_tracker_decision(finding)
    assert out is False
