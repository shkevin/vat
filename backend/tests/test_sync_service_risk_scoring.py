from unittest.mock import AsyncMock

import pytest

from app.models.finding import Finding, FindingType, Severity, Status
from app.services import sync_service


@pytest.mark.asyncio
async def test_tracker_decision_body_includes_environmental_scoring(monkeypatch):
    finding = Finding(
        id="f-risk",
        finding_type=FindingType.SCA,
        fingerprint_id="fp-risk",
        cve_id="CVE-2024-23342",
        severity=Severity.High,
        status=Status.RiskAccepted,
        title="python-ecdsa: vulnerable to the Minerva attack",
        external_links=[
            {
                "kind": "tracker",
                "adapter_key": "linear",
                "issue_id": "VAT-123",
            }
        ],
        risk_scoring={
            "source": {"score": "7.4", "severity": "High"},
            "environmental": {
                "score": "0.0",
                "rationale": "Vulnerable ECDSA signing path is not reachable.",
                "knownScannerException": "Trivy reports one High in the core image.",
            },
        },
    )
    enqueue_spy = AsyncMock(return_value=object())
    monkeypatch.setattr(sync_service, "enqueue_sync_event", enqueue_spy)

    await sync_service.enqueue_tracker_post_decision(
        AsyncMock(), finding, "linear", "reviewer@example.com"
    )

    payload = enqueue_spy.await_args.kwargs["payload"]
    assert payload["tracker_issue_id"] == "VAT-123"
    assert "**Environmental score:** 0.0" in payload["body"]
    assert (
        "**Environmental rationale:** Vulnerable ECDSA signing path is not reachable."
        in payload["body"]
    )
    assert "**Known scanner exception:** Trivy reports one High in the core image." in payload["body"]
