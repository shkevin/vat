from unittest.mock import AsyncMock

import pytest

from app.models.finding import Finding, FindingType, Severity, Status
from app.services import findings_service


def _finding() -> Finding:
    return Finding(
        id="audit-finding",
        finding_type=FindingType.SCA,
        fingerprint_id="fp-audit-finding",
        cve_id="CVE-2026-0001",
        severity=Severity.High,
        status=Status.Open,
        component="openssl",
        audit=[],
        tracker_comment=False,
        archived=False,
        external_links=[],
        regression_count=0,
    )


@pytest.mark.asyncio
async def test_update_finding_records_status_decision_in_audit(monkeypatch):
    finding = _finding()
    db = AsyncMock()
    monkeypatch.setattr(findings_service, "get_finding", AsyncMock(return_value=finding))
    monkeypatch.setattr(
        findings_service, "_enqueue_sync_on_status_change", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "_enqueue_tracker_update_issue_if_supported", AsyncMock()
    )
    emit_spy = AsyncMock(return_value="audit-event-id")
    monkeypatch.setattr(findings_service, "emit_audit_event", emit_spy, raising=False)
    monkeypatch.setattr(
        findings_service, "new_trace_id", lambda: "trace-review", raising=False
    )

    await findings_service.update_finding(
        db,
        finding.id,
        {"status": "Risk Accepted", "reviewer_note": "accepted for 30 days"},
        user="reviewer@example.com",
    )

    assert finding.audit[-1]["user"] == "reviewer@example.com"
    assert finding.audit[-1]["action"] == "Status \u2192 Risk Accepted"
    assert finding.audit[-1]["note"] == "accepted for 30 days"
    emit_spy.assert_awaited_once()
    event = emit_spy.await_args.kwargs
    assert event["trace_id"] == "trace-review"
    assert event["event_type"] == "finding.audit"
    assert event["actor_type"] == "user"
    assert event["actor_id"] == "reviewer@example.com"
    assert event["finding_id"] == finding.id
    assert event["decision_name"] == "Status \u2192 Risk Accepted"
    assert event["decision_reason_code"] == "status_change"
    assert event["decision_result"] == "Risk Accepted"
    assert event["data"]["previousStatus"] == "Open"
    assert event["data"]["status"] == "Risk Accepted"
    assert event["note"] == "accepted for 30 days"


@pytest.mark.asyncio
async def test_update_finding_records_reviewer_note_changes_in_audit(monkeypatch):
    finding = _finding()
    db = AsyncMock()
    monkeypatch.setattr(findings_service, "get_finding", AsyncMock(return_value=finding))
    monkeypatch.setattr(
        findings_service, "_enqueue_sync_on_status_change", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "_enqueue_tracker_update_issue_if_supported", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "emit_audit_event", AsyncMock(return_value="audit-event-id")
    )
    monkeypatch.setattr(findings_service, "new_trace_id", lambda: "trace-review")

    await findings_service.update_finding(
        db,
        finding.id,
        {"reviewer_note": "needs app owner confirmation"},
        user="reviewer@example.com",
    )

    assert finding.audit[-1]["action"] == "Reviewer note updated"
    assert finding.audit[-1]["note"] == "needs app owner confirmation"


@pytest.mark.asyncio
async def test_update_finding_merges_environmental_risk_scoring(monkeypatch):
    finding = _finding()
    finding.risk_scoring = {
        "source": {
            "source": "trivy",
            "score": "7.4",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        }
    }
    db = AsyncMock()
    monkeypatch.setattr(findings_service, "get_finding", AsyncMock(return_value=finding))
    monkeypatch.setattr(
        findings_service, "_enqueue_sync_on_status_change", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "_enqueue_tracker_update_issue_if_supported", AsyncMock()
    )
    emit_spy = AsyncMock(return_value="audit-event-id")
    monkeypatch.setattr(findings_service, "emit_audit_event", emit_spy)
    monkeypatch.setattr(findings_service, "new_trace_id", lambda: "trace-review")
    monkeypatch.setattr(findings_service, "_now", lambda: "2026-06-26T20:55:00Z")

    await findings_service.update_finding(
        db,
        finding.id,
        {
            "risk_scoring": {
                "environmental": {
                    "cvssVersion": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/MC:N/MI:N/MA:N",
                    "score": "0.0",
                    "rationale": "Vulnerable ECDSA signing path is not reachable.",
                    "knownScannerException": "Trivy reports one High in the core image.",
                    "scopeNote": "Generated container image scan set.",
                }
            }
        },
        user="reviewer@example.com",
    )

    assert finding.risk_scoring["source"]["score"] == "7.4"
    assert finding.risk_scoring["environmental"]["score"] == "0.0"
    assert finding.risk_scoring["environmental"]["updatedBy"] == "reviewer@example.com"
    assert (
        finding.risk_scoring["environmental"]["updatedAt"] == "2026-06-26T20:55:00Z"
    )
    assert finding.audit[-1]["action"] == "Environmental scoring updated"
    assert finding.audit[-1]["note"] == "Vulnerable ECDSA signing path is not reachable."
    event = emit_spy.await_args.kwargs
    assert event["decision_reason_code"] == "risk_scoring"


@pytest.mark.asyncio
async def test_update_finding_computes_environmental_score_from_cvss_vector(monkeypatch):
    finding = _finding()
    finding.risk_scoring = {}
    db = AsyncMock()
    monkeypatch.setattr(findings_service, "get_finding", AsyncMock(return_value=finding))
    monkeypatch.setattr(
        findings_service, "_enqueue_sync_on_status_change", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "_enqueue_tracker_update_issue_if_supported", AsyncMock()
    )
    monkeypatch.setattr(
        findings_service, "emit_audit_event", AsyncMock(return_value="audit-event-id")
    )
    monkeypatch.setattr(findings_service, "new_trace_id", lambda: "trace-review")
    monkeypatch.setattr(findings_service, "_now", lambda: "2026-06-26T21:00:00Z")

    await findings_service.update_finding(
        db,
        finding.id,
        {
            "risk_scoring": {
                "environmental": {
                    "cvssVersion": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N",
                    "rationale": "Vulnerable operation is not reachable.",
                }
            }
        },
        user="reviewer@example.com",
    )

    assert finding.risk_scoring["environmental"]["score"] == "0.0"
