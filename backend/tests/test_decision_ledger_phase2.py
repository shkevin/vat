"""Phase 2 decision ledger unit tests (no database)."""

from types import SimpleNamespace

from app.models.finding import Status
from app.services.decision_ledger import (
    _is_waiver_expired,
    _waiver_matches_asset,
    should_apply_decision,
    waiver_records_for_export,
)


def test_is_waiver_expired() -> None:
    assert _is_waiver_expired("2020-01-01", today="2025-06-01") is True
    assert _is_waiver_expired("2020-01-01T00:00:00Z", today="2025-06-01") is True
    assert _is_waiver_expired("2999-01-01", today="2025-06-01") is False
    assert _is_waiver_expired(None, today="2025-06-01") is False


def test_waiver_matches_asset() -> None:
    rec = {"image": "api-server:latest", "component": "openssl"}
    assert _waiver_matches_asset(rec, "api-server:latest") is True
    assert _waiver_matches_asset(rec, "other:latest") is False
    assert _waiver_matches_asset(rec, "") is True


def test_waiver_records_for_export_shape() -> None:
    rows = waiver_records_for_export(
        [
            {
                "decisionId": "td-1",
                "subjectKey": "decision:v1:t1:sca:...",
                "findingId": "f-1",
                "linked": True,
                "cveId": "CVE-1",
                "attestation": {"waiverRef": "W-1", "expiresAt": "2099-01-01"},
                "justification": "accepted",
            }
        ]
    )
    assert rows[0]["decisionId"] == "td-1"
    assert rows[0]["waiverRef"] == "W-1"
    assert rows[0]["justification"] == "accepted"


def test_should_apply_decision_reapplies_on_edit() -> None:
    decision = SimpleNamespace(status=Status.RiskAccepted.value, decision_version=2)
    # Finding already Risk Accepted but link only reflected version 1 -> re-project edit.
    stale = SimpleNamespace(status=Status.RiskAccepted, _decision_applied_version=1)
    assert should_apply_decision(stale, decision) is True
    # Link already at the current version -> no-op.
    current = SimpleNamespace(status=Status.RiskAccepted, _decision_applied_version=2)
    assert should_apply_decision(current, decision) is False
    # Open finding -> apply because the decision auto-applies.
    fresh = SimpleNamespace(status=Status.Open)
    assert should_apply_decision(fresh, decision) is True
