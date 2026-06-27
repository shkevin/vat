"""Phase 2 decision ledger unit tests (no database)."""

from datetime import datetime
from types import SimpleNamespace

from app.models.finding import Status
from app.services.decision_ledger import (
    _is_waiver_expired,
    _rekey_subject_key_asset,
    _waiver_matches_asset,
    decision_apply_action,
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


def test_decision_apply_action_conflict_policy() -> None:
    # Approved/Rejected are never auto-applied — flagged for reviewer confirmation.
    approved = SimpleNamespace(status=Status.Approved.value, decision_version=1, updated_at=None)
    open_f = SimpleNamespace(status=Status.Open)
    assert decision_apply_action(open_f, approved) == "conflict"

    # Terminal decision onto a finding a human edited AFTER the decision -> conflict.
    decision = SimpleNamespace(
        status=Status.RiskAccepted.value,
        decision_version=2,
        updated_at=datetime(2026, 1, 1, 0, 0, 0),
    )
    edited = SimpleNamespace(
        status=Status.FalsePositive,  # diverged from decision
        _decision_applied_version=1,
        audit=[{"ts": "2026-02-01T00:00:00Z", "user": "alice@co", "action": "edit"}],
    )
    assert decision_apply_action(edited, decision) == "conflict"

    # Same edit but only a system audit entry -> safe to apply.
    system_only = SimpleNamespace(
        status=Status.FalsePositive,
        _decision_applied_version=1,
        audit=[{"ts": "2026-02-01T00:00:00Z", "user": "system", "action": "x"}],
    )
    assert decision_apply_action(system_only, decision) == "apply"


def test_rekey_subject_key_asset() -> None:
    key = "decision:v1:t-default:sca:docker.io/library/api|main|:openssl:cve-2024-1"
    out = _rekey_subject_key_asset(key, "docker.io/library/api", "docker.io/library/web")
    assert out == "decision:v1:t-default:sca:docker.io/library/web|main|:openssl:cve-2024-1"
    # Token not in asset position -> no rewrite.
    assert _rekey_subject_key_asset(key, "openssl", "x") is None
