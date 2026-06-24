from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.finding import Status
from app.schemas.auth import UserContext
from app.services.assets_service import _build_asset_payload, get_assets_with_findings
from app.services.metric_semantics import (
    is_closed_disposition,
    is_open_risk,
    is_overdue_open_risk,
    is_risk_accepted,
    is_verified_disposition,
)


def test_risk_accepted_is_its_own_bucket() -> None:
    assert is_risk_accepted("Risk Accepted")
    assert is_risk_accepted("RiskAccepted")
    assert is_risk_accepted(Status.RiskAccepted)
    assert not is_closed_disposition("Risk Accepted")
    assert not is_open_risk("Risk Accepted")


def test_active_workflow_statuses_are_open_risk() -> None:
    for status in (
        Status.Open,
        Status.InReview,
        "In Review",
        Status.Reopened,
        Status.Rejected,
        Status.Mitigated,
    ):
        assert is_open_risk(status), status


def test_closed_dispositions_are_verified_not_open_risk() -> None:
    for status in (
        Status.Resolved,
        Status.FalsePositive,
        "False Positive",
        Status.Duplicate,
        "Not Applicable",
        Status.Approved,
        Status.Suppressed,
        "closed",
        "ignored",
        "auto_ignored",
    ):
        assert is_closed_disposition(status), status
        assert is_verified_disposition(status), status
        assert not is_open_risk(status), status


def test_only_open_risk_findings_are_overdue() -> None:
    as_of = "2026-06-18T12:00:00Z"
    yesterday = "2026-06-17T00:00:00Z"

    assert is_overdue_open_risk(Status.Reopened, yesterday, as_of=as_of)
    assert not is_overdue_open_risk(Status.RiskAccepted, yesterday, as_of=as_of)
    assert not is_overdue_open_risk(Status.Resolved, yesterday, as_of=as_of)


def test_asset_payload_uses_open_risk_for_rollups() -> None:
    payload = _build_asset_payload(
        "openssl",
        [
            {
                "id": "waived-critical",
                "status": "Risk Accepted",
                "severity": "Critical",
                "slaDue": "2026-06-17T00:00:00Z",
            },
            {
                "id": "reopened-high",
                "status": "Reopened",
                "severity": "High",
                "slaDue": "2026-06-17T00:00:00Z",
            },
            {
                "id": "resolved-medium",
                "status": "Resolved",
                "severity": "Medium",
                "slaDue": "2026-06-17T00:00:00Z",
            },
        ],
        include_findings=False,
    )

    assert payload["openCount"] == 1
    assert payload["overdueCount"] == 1
    assert payload["verifiedPct"] == 33.3
    assert payload["oraPct"] == 96


@pytest.mark.asyncio
async def test_zero_finding_assets_do_not_require_asset_tenant_column() -> None:
    class _ScalarResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _ExecuteResult:
        def __init__(self, rows):
            self._rows = rows

        def scalars(self):
            return _ScalarResult(self._rows)

    db = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _ExecuteResult(
                    [
                        SimpleNamespace(
                            id="zero-asset",
                            name="Zero Asset",
                            type="repo",
                            branch="main",
                            tag=None,
                        )
                    ]
                ),
                _ExecuteResult([]),
                _ExecuteResult([]),
            ]
        )
    )
    ctx = UserContext(
        user_id="admin",
        email="admin@vat.local",
        tenant_id="t-default",
        role="admin",
        raw_identity="admin@vat.local",
    )

    assets = await get_assets_with_findings(
        db,
        findings_dicts=[],
        ctx=ctx,
        include_zero_assets=True,
    )

    assert assets[0]["id"] == "zero-asset"
    assert db.execute.await_count == 3


@pytest.mark.asyncio
async def test_persisted_only_assets_excludes_finding_derived_groups() -> None:
    class _ScalarResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _ExecuteResult:
        def __init__(self, rows):
            self._rows = rows

        def scalars(self):
            return _ScalarResult(self._rows)

    db = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _ExecuteResult(
                    [
                        SimpleNamespace(
                            id="persisted-asset",
                            name="Persisted Asset",
                            type="container",
                            branch=None,
                            tag=None,
                        )
                    ]
                ),
                _ExecuteResult([]),
                _ExecuteResult([]),
            ]
        )
    )

    assets = await get_assets_with_findings(
        db,
        findings_dicts=[
            {"id": "f1", "image": "persisted-asset", "status": "Open", "severity": "High"},
            {"id": "f2", "image": "derived-only", "status": "Open", "severity": "High"},
        ],
        include_zero_assets=True,
        include_finding_derived_assets=False,
    )

    assert [a["id"] for a in assets] == ["persisted-asset"]
    assert [f["id"] for f in assets[0]["findings"]] == ["f1"]
