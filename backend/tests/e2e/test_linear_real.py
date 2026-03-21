"""
E2E tests for Linear integration against a real Linear workspace.

Uses the existing Linear configuration from VAT settings (DB or env).
Configure Linear in Settings → Tracker before running these tests.

Run:
  cd backend && uv run pytest tests/e2e/test_linear_real.py -v
  uv run pytest -m e2e_linear -v
"""

import time
from datetime import datetime, timezone

import pytest


pytestmark = [pytest.mark.e2e_linear]


@pytest.fixture
async def linear_credentials(db):
    """Get Linear credentials from DB (VAT settings) or env. Skips if not configured."""
    from app.api.settings import get_linear_credentials

    api_key, team_id, _ = await get_linear_credentials(db)
    if not api_key or not team_id:
        pytest.skip("Linear not configured. Configure in VAT Settings → Tracker.")
    return api_key, team_id


@pytest.fixture
def linear_adapter(linear_credentials):
    """Linear adapter using credentials from VAT settings."""
    from app.adapters.linear import LinearAdapter

    api_key, team_id = linear_credentials
    return LinearAdapter(api_key=api_key, team_id=team_id)


@pytest.fixture
def unique_cve_id():
    """Unique CVE-like ID for test isolation (avoids collisions across runs)."""
    ts = int(time.time())
    return f"CVE-2099-{ts % 100000:05d}"


# ---------------------------------------------------------------------------
# Adapter API tests (create, post, list, find)
# ---------------------------------------------------------------------------


async def test_linear_create_issue(linear_adapter, unique_cve_id):
    """Create a Linear issue with [VAT] template. Verifies outbound sync."""
    from app.schemas.vat import VatTrackerCreateIssueRequest

    req = VatTrackerCreateIssueRequest(
        finding={
            "cveId": unique_cve_id,
            "title": f"E2E test: {unique_cve_id}",
            "severity": "high",
        },
        template="[VAT] {cve_id}\nstatus: false-positive | not-applicable | risk-accepted | mitigated | duplicate\njustification: <required>\ncompensating-controls: <optional>",
    )
    identifier = await linear_adapter.create_issue(req)
    assert identifier
    assert "-" in identifier  # e.g. ENG-123


async def test_linear_post_comment(linear_adapter, unique_cve_id):
    """Create issue, then post a comment. Verifies comment creation."""
    from app.schemas.vat import (
        VatTrackerCreateIssueRequest,
        VatTrackerPostDecisionRequest,
    )

    req = VatTrackerCreateIssueRequest(
        finding={
            "cveId": unique_cve_id,
            "title": f"E2E comment test: {unique_cve_id}",
            "severity": "medium",
        },
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
    )
    identifier = await linear_adapter.create_issue(req)
    assert identifier

    post_req = VatTrackerPostDecisionRequest(
        tracker_issue_id=identifier,
        body="E2E test comment: VAT reviewer decision posted successfully.",
    )
    await linear_adapter.post_comment(post_req)
    # No exception = success


async def test_linear_list_issues(linear_adapter):
    """List issues from the team. Verifies list_issues and pagination."""
    nodes, cursor = await linear_adapter.list_issues(
        first=5,
        include_archived=False,
        include_comments=False,
    )
    assert isinstance(nodes, list)
    # May be empty in fresh workspace
    for node in nodes:
        assert "identifier" in node or "id" in node
        assert "title" in node or "description" in node


async def test_linear_find_existing_issue_for_cve(linear_adapter, unique_cve_id):
    """Create issue with CVE, then find_existing_issue_for_cve returns it."""
    from app.schemas.vat import VatTrackerCreateIssueRequest

    req = VatTrackerCreateIssueRequest(
        finding={
            "cveId": unique_cve_id,
            "title": f"E2E find test: {unique_cve_id}",
            "severity": "low",
        },
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
    )
    created_id = await linear_adapter.create_issue(req)
    assert created_id

    found = await linear_adapter.find_existing_issue_for_cve(unique_cve_id)
    assert found == created_id


async def test_linear_find_existing_issue_for_cve_not_found(linear_adapter):
    """find_existing_issue_for_cve returns None for non-existent CVE."""
    found = await linear_adapter.find_existing_issue_for_cve(
        "CVE-1999-00000-nonexistent"
    )
    assert found is None


# ---------------------------------------------------------------------------
# Webhook simulation (POST to /webhook/linear)
# ---------------------------------------------------------------------------


async def test_linear_webhook_comment_create(
    client, db, unique_cve_id, linear_credentials
):
    """
    Simulate Linear Comment.create webhook with [VAT] block.
    Uses Linear credentials from VAT settings. Creates finding with matching CVE.
    """
    from app.models.finding import Finding, FindingType, Severity, Status
    from app.services.dedup import make_fingerprint
    from sqlalchemy import select

    # Create finding with matching CVE (apply_vat_parsed_update finds by cve_id)
    fp = make_fingerprint(unique_cve_id, "e2e-test")
    finding_id = f"f-{fp[:8]}"
    finding = Finding(
        id=finding_id,
        fingerprint_id=fp,
        cve_id=unique_cve_id,
        finding_type=FindingType.SCA,
        severity=Severity.High,
        status=Status.Open,
        title=f"E2E webhook test {unique_cve_id}",
    )
    db.add(finding)
    await db.commit()

    # Simulate Linear webhook payload (Comment.create with [VAT] block)
    webhook_payload = {
        "action": "create",
        "type": "Comment",
        "webhookTimestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
        "data": {
            "body": f"[VAT] {unique_cve_id}\nstatus: false-positive\njustification: E2E test",
            "id": f"comment-e2e-{int(time.time())}",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "issue": {
                "identifier": "E2E-1",
                "id": "issue-e2e-uuid",
                "title": f"E2E {unique_cve_id}",
                "description": "",
            },
        },
    }

    response = await client.post("/webhook/linear", json=webhook_payload)

    assert response.status_code == 200, f"Webhook failed: {response.text}"

    # Verify finding updated in VAT (round-trip: Linear → VAT via webhook)
    # Webhook uses its own session; expire cache so we see committed updates
    db.expire_all()
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    updated = r.scalar_one_or_none()
    assert updated is not None
    assert updated.status == Status.FalsePositive
    assert "E2E test" in (updated.justification or "")


# ---------------------------------------------------------------------------
# Poll service (full flow with DB)
# ---------------------------------------------------------------------------


async def test_linear_poll_for_updates(db, linear_credentials):
    """
    Run poll_linear_for_updates against real Linear.
    Verifies: list_issues, parse [VAT] blocks, apply_vat_parsed_update.
    """
    from app.services.linear_poll_service import poll_linear_for_updates

    result = await poll_linear_for_updates(db, force=True)
    assert "issues_fetched" in result
    assert "comments_processed" in result
    assert "descriptions_processed" in result
    assert "errors" in result
    assert isinstance(result["errors"], list)


# ---------------------------------------------------------------------------
# Round-trip sync: verify changes propagate both directions
# ---------------------------------------------------------------------------


async def test_roundtrip_vat_to_linear(linear_adapter, db, unique_cve_id):
    """
    VAT → Linear: Create finding in VAT, sync to Linear, verify issue exists in Linear.
    """
    from app.models.finding import Finding, FindingType, Severity, Status
    from app.services.dedup import make_fingerprint
    from app.schemas.vat import VatTrackerCreateIssueRequest

    # 1. Create finding in VAT
    fp = make_fingerprint(unique_cve_id, "e2e-roundtrip")
    finding_id = f"f-{fp[:8]}"
    title = f"E2E roundtrip VAT→Linear: {unique_cve_id}"
    finding = Finding(
        id=finding_id,
        fingerprint_id=fp,
        cve_id=unique_cve_id,
        finding_type=FindingType.SCA,
        severity=Severity.High,
        status=Status.Open,
        title=title,
    )
    db.add(finding)
    await db.commit()

    # 2. Sync to Linear (create issue)
    template = "[VAT] {cve_id}\nstatus: false-positive | not-applicable | risk-accepted | mitigated | duplicate\njustification: <required>\ncompensating-controls: <optional>"
    req = VatTrackerCreateIssueRequest(
        finding={"cveId": unique_cve_id, "title": title, "severity": "high"},
        template=template,
    )
    identifier = await linear_adapter.create_issue(req)
    assert identifier, "Linear issue creation failed"

    # 3. Verify in Linear: fetch issues and find ours
    nodes, _ = await linear_adapter.list_issues(first=100, include_archived=False)
    found = next(
        (n for n in nodes if (n.get("identifier") or "").upper() == identifier.upper()),
        None,
    )
    assert found is not None, f"Issue {identifier} not found in Linear"
    assert unique_cve_id in (found.get("title") or ""), "Title should contain CVE"
    desc = found.get("description") or ""
    # Linear may return markdown-escaped brackets (\ [VAT\]); check for template content
    assert (
        "VAT" in desc and "status:" in desc and unique_cve_id in desc
    ), "Description should contain [VAT] template"


async def test_roundtrip_linear_to_vat(linear_adapter, db, unique_cve_id):
    """
    Linear → VAT: Create finding in VAT, create Linear issue with [VAT] comment, poll, verify finding updated.
    """
    from app.models.finding import Finding, FindingType, Severity, Status
    from app.services.dedup import make_fingerprint
    from app.schemas.vat import (
        VatTrackerCreateIssueRequest,
        VatTrackerPostDecisionRequest,
    )
    from app.services.linear_poll_service import poll_linear_for_updates
    from sqlalchemy import select

    # 1. Create finding in VAT (poll matches by cve_id)
    fp = make_fingerprint(unique_cve_id, "e2e-roundtrip-in")
    finding_id = f"f-{fp[:8]}"
    finding = Finding(
        id=finding_id,
        fingerprint_id=fp,
        cve_id=unique_cve_id,
        finding_type=FindingType.SCA,
        severity=Severity.High,
        status=Status.Open,
        title=f"E2E roundtrip Linear→VAT: {unique_cve_id}",
    )
    db.add(finding)
    await db.commit()

    # 2. Create Linear issue with CVE in title (so poll can associate)
    req = VatTrackerCreateIssueRequest(
        finding={
            "cveId": unique_cve_id,
            "title": f"E2E {unique_cve_id}",
            "severity": "medium",
        },
        template="[VAT] {cve_id}\nstatus: ...\njustification: ...",
    )
    identifier = await linear_adapter.create_issue(req)
    assert identifier

    # 3. Add [VAT] comment in Linear (simulates engineer adding decision)
    vat_block = f"[VAT] {unique_cve_id}\nstatus: risk-accepted\njustification: E2E roundtrip verification"
    await linear_adapter.post_comment(
        VatTrackerPostDecisionRequest(tracker_issue_id=identifier, body=vat_block)
    )

    # 4. Poll Linear to sync comment into VAT
    result = await poll_linear_for_updates(db, force=True)
    assert result.get("errors") == [], f"Poll errors: {result.get('errors')}"

    # 5. Verify finding updated in VAT (re-fetch to avoid stale session state)
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    updated = r.scalar_one_or_none()
    assert updated is not None, "Finding not found after poll"
    assert (
        updated.status == Status.RiskAccepted
    ), f"Expected RiskAccepted, got {updated.status}"
    assert "E2E roundtrip" in (
        updated.justification or ""
    ), f"Expected justification, got {updated.justification}"
