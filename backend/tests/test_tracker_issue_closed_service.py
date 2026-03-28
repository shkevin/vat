from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.finding import Status
from app.services import tracker_issue_closed


@pytest.mark.asyncio
async def test_tracker_issue_closed_state_not_closed():
    adapter = SimpleNamespace(is_state_closed=AsyncMock(return_value=False))
    out = await tracker_issue_closed.handle_tracker_issue_closed_without_vat(
        db=SimpleNamespace(),
        adapter=adapter,
        issue_id="iss-1",
        issue_uuid="uuid-1",
        state_id="st-1",
        api_key="k",
        team_id="t",
    )
    assert out == {"reopened": False, "finding_id": None, "reason": "state not closed"}


@pytest.mark.asyncio
async def test_tracker_issue_closed_no_finding_then_terminal(monkeypatch):
    adapter = SimpleNamespace(
        is_state_closed=AsyncMock(return_value=True),
        reopen_issue=AsyncMock(return_value=True),
    )

    async def fake_find_none(_db, _adapter_key, _ext):
        return None

    monkeypatch.setattr(tracker_issue_closed, "find_finding_by_external_id", fake_find_none)
    out = await tracker_issue_closed.handle_tracker_issue_closed_without_vat(
        db=SimpleNamespace(),
        adapter=adapter,
        issue_id="iss-1",
        issue_uuid="uuid-1",
        state_id="st-1",
        api_key="k",
        team_id="t",
    )
    assert out == {"reopened": False, "finding_id": None, "reason": "no linked finding"}
    assert adapter.reopen_issue.await_count == 0

    finding = SimpleNamespace(id="f1", status=Status.Approved)

    async def fake_find_terminal(_db, _adapter_key, _ext):
        return finding

    monkeypatch.setattr(
        tracker_issue_closed, "find_finding_by_external_id", fake_find_terminal
    )
    out2 = await tracker_issue_closed.handle_tracker_issue_closed_without_vat(
        db=SimpleNamespace(),
        adapter=adapter,
        issue_id="iss-1",
        issue_uuid="uuid-1",
        state_id="st-1",
        api_key="k",
        team_id="t",
    )
    assert out2 == {
        "reopened": False,
        "finding_id": "f1",
        "reason": "finding already terminal",
    }


@pytest.mark.asyncio
async def test_tracker_issue_closed_reopen_success_and_failure(monkeypatch):
    finding = SimpleNamespace(id="f-open", status=Status.Open)
    adapter = SimpleNamespace(
        is_state_closed=AsyncMock(return_value=True),
        reopen_issue=AsyncMock(side_effect=[True, False]),
    )

    async def fake_find(_db, _adapter_key, _ext):
        return finding

    monkeypatch.setattr(tracker_issue_closed, "find_finding_by_external_id", fake_find)

    ok = await tracker_issue_closed.handle_tracker_issue_closed_without_vat(
        db=SimpleNamespace(),
        adapter=adapter,
        issue_id="iss-1",
        issue_uuid="uuid-1",
        state_id="st-1",
        api_key="k",
        team_id="t",
    )
    assert ok == {
        "reopened": True,
        "finding_id": "f-open",
        "reason": "reopened to prevent drift",
    }

    failed = await tracker_issue_closed.handle_tracker_issue_closed_without_vat(
        db=SimpleNamespace(),
        adapter=adapter,
        issue_id="iss-1",
        issue_uuid="uuid-1",
        state_id="st-1",
        api_key="k",
        team_id="t",
    )
    assert failed == {
        "reopened": False,
        "finding_id": "f-open",
        "reason": "reopen failed",
    }
