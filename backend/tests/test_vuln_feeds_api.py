"""Tests for vulnerability feed APIs."""

import pytest

from app.core.auth import get_current_user_context, require_admin
from app.main import app
from app.schemas.auth import UserContext


@pytest.mark.asyncio
async def test_vuln_feeds_summary_and_runs(client, monkeypatch):
    async def fake_current_user():
        return UserContext(
            user_id="u1",
            email="reviewer@vat.local",
            tenant_id="t-default",
            role="reviewer",
            raw_identity="reviewer@vat.local",
        )

    async def fake_summary(_db):
        return {"total_records": 3, "severity_breakdown": {}, "sources": []}

    async def fake_top(_db, limit=20):
        return [{"vulnerability_id": "CVE-2026-1000", "count": 2}]

    async def fake_runs(_db, source=None, limit=100):
        return [
            {
                "id": "run1",
                "source": source or "osv",
                "status": "completed",
                "trace_id": "trace1",
                "stats": {"fetched_items": 1},
                "error": None,
                "started_at": None,
                "completed_at": None,
            }
        ]

    async def fake_records(
        _db, source=None, severity=None, search=None, limit=50, offset=0
    ):
        return {"total": 1, "count": 1, "records": [{"id": 1, "source": source or "osv"}]}

    monkeypatch.setattr("app.api.vuln_feeds.get_feed_summary", fake_summary)
    monkeypatch.setattr("app.api.vuln_feeds.top_vulnerabilities", fake_top)
    monkeypatch.setattr("app.api.vuln_feeds.get_feed_runs", fake_runs)
    monkeypatch.setattr("app.api.vuln_feeds.get_feed_records", fake_records)
    app.dependency_overrides[get_current_user_context] = fake_current_user
    try:
        summary_res = await client.get("/api/vuln-feeds/summary")
        assert summary_res.status_code == 200
        payload = summary_res.json()
        assert payload["total_records"] == 3
        assert payload["top_vulnerabilities"][0]["vulnerability_id"] == "CVE-2026-1000"

        runs_res = await client.get("/api/vuln-feeds/runs?source=osv&limit=10")
        assert runs_res.status_code == 200
        assert runs_res.json()["count"] == 1

        records_res = await client.get(
            "/api/vuln-feeds/records?source=osv&severity=HIGH&search=openssl&limit=25&offset=0"
        )
        assert records_res.status_code == 200
        assert records_res.json()["count"] == 1
    finally:
        app.dependency_overrides.pop(get_current_user_context, None)


@pytest.mark.asyncio
async def test_vuln_feeds_refresh_requires_admin(client, monkeypatch):
    async def fake_admin():
        return UserContext(
            user_id="admin",
            email="admin@vat.local",
            tenant_id="t-default",
            role="admin",
            raw_identity="admin@vat.local",
        )

    async def fake_refresh(_db, trace_id=None, actor_id="system"):
        return {"enabled": True, "sources": ["osv"], "stats": []}

    monkeypatch.setattr("app.api.vuln_feeds.refresh_enabled_feeds", fake_refresh)
    app.dependency_overrides[require_admin] = fake_admin
    try:
        res = await client.post("/api/vuln-feeds/refresh?use_celery=false")
        assert res.status_code == 200
    finally:
        app.dependency_overrides.pop(require_admin, None)
