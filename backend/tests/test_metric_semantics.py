from app.models.finding import Status
from app.services.assets_service import _build_asset_payload
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
