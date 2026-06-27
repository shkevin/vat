"""Unit tests to raise coverage on core service/task helpers."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.registry import TrackerAdapterCapabilities
from app.core.retry import retry_async
from app.models.finding import Status
from app.services import (
    linear_parsed_service,
    linear_poll_service,
    openscap_storage,
    tracker_notify,
    waiver_expiry,
    watched_label_inject,
)
from app.tasks import audit_tasks, sync_tasks


@pytest.mark.asyncio
async def test_retry_async_success_and_failure(monkeypatch):
    calls = {"n": 0}

    async def _ok():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("try again")
        return "ok"

    sleeps = []

    async def _sleep(delay: float):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    assert await retry_async(_ok, max_attempts=3, base_delay=0.1) == "ok"
    assert sleeps == [0.1]

    async def _bad():
        raise ValueError("fail")

    with pytest.raises(ValueError):
        await retry_async(_bad, max_attempts=2, base_delay=0.01)


@pytest.mark.asyncio
async def test_notify_tracker_decision_paths(monkeypatch):
    finding = SimpleNamespace(
        id="f1",
        status=Status.Approved,
        reviewer_note="note",
        justification="because",
        attestation={"waiverRef": "W-1", "expiresAt": "2026-12-01"},
    )
    monkeypatch.setattr(
        "app.services.external_links_service.get_tracker_issue_id",
        lambda finding, tracker_key: "VAT-1",
    )
    monkeypatch.setattr("app.services.tracker_notify.get_settings", lambda: SimpleNamespace(linear_api_key="x"))

    class _Linear:
        async def post_comment(self, issue_id, body):
            assert issue_id == "VAT-1"
            assert "VAT Reviewer Decision" in body

    monkeypatch.setattr(tracker_notify, "LinearAdapter", _Linear)
    assert await tracker_notify.notify_tracker_decision(finding, user="u@test") is True

    finding.status = Status.Open
    assert await tracker_notify.notify_tracker_decision(finding) is False

    finding.status = Status.Approved
    monkeypatch.setattr(
        "app.services.external_links_service.get_tracker_issue_id",
        lambda finding, tracker_key: None,
    )
    assert await tracker_notify.notify_tracker_decision(finding) is False


@pytest.mark.asyncio
async def test_waiver_expiry_enforcement(monkeypatch):
    old = SimpleNamespace(
        status=Status.RiskAccepted,
        attestation={"expiresAt": "2020-01-01", "waiverRef": "W-OLD"},
        audit=[],
    )
    future = SimpleNamespace(
        status=Status.RiskAccepted,
        attestation={"expiresAt": "2999-01-01"},
        audit=[],
    )

    class _Res:
        def scalars(self):
            return SimpleNamespace(all=lambda: [old, future])

    class _DB:
        def __init__(self):
            self.committed = False

        async def execute(self, q):
            return _Res()

        async def commit(self):
            self.committed = True

    db = _DB()

    class _Ctx:
        async def __aenter__(self):
            return db

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(waiver_expiry, "async_session", lambda: _Ctx())
    monkeypatch.setattr(
        waiver_expiry,
        "get_settings",
        lambda: SimpleNamespace(decision_ledger_enabled=False),
    )
    count = await waiver_expiry.enforce_waiver_expiry()
    assert count == 1
    assert old.status == Status.Open
    assert db.committed is True


@pytest.mark.asyncio
async def test_openscap_storage_helpers(monkeypatch):
    assert openscap_storage._extract_benchmark_id_from_xml(b"<Benchmark id='bench-1'/>") == "bench-1"
    assert openscap_storage._extract_benchmark_id_from_xml(b"<oval_results/>") == "oval_results"
    assert openscap_storage._extract_benchmark_id_from_xml(b"{") is None

    db = SimpleNamespace(
        get=AsyncMock(return_value=None),
        execute=AsyncMock(),
        add=MagicMock(),
        commit=AsyncMock(),
    )
    await openscap_storage.store_openscap_scan_result(
        db,
        b"<Benchmark id='bench-1'/>",
        parser_id="openscap",
        source_id="src",
        asset_id="asset",
        tenant_id="t1",
    )
    assert db.get.await_count == 1
    assert db.execute.await_count == 1
    assert db.add.call_count == 2  # evidence blob + scan result row
    assert db.commit.await_count == 1

    class _Res:
        def __init__(self, rows):
            self._rows = rows

        def scalars(self):
            return SimpleNamespace(all=lambda: self._rows)

    row_a = SimpleNamespace(raw_xccdf_xml=b"inline-a", evidence_sha256=None)
    row_b = SimpleNamespace(raw_xccdf_xml=b"inline-b", evidence_sha256=None)
    db2 = SimpleNamespace(execute=AsyncMock(return_value=_Res([row_a, row_b])))
    rows = await openscap_storage.list_openscap_scan_results(db2, tenant_id="t1")
    assert rows == [row_a, row_b]


@pytest.mark.asyncio
async def test_watched_label_helpers_and_handlers(monkeypatch):
    assert watched_label_inject._label_ids_from_issue({"issue": {"labelIds": ["a"]}}) == ["a"]
    assert watched_label_inject._label_ids_from_issue({"issue": {"labels": {"nodes": [{"id": "x"}]}}}) == ["x"]
    assert watched_label_inject._label_ids_from_updated_from({"labelIds": ["p"]}) == ["p"]

    async def _labels(_db):
        return [{"name": "vat"}]

    async def _template(_db):
        return "[VAT] status:"

    async def _creds(_db):
        return ("api", "team", "secret")

    class _Adapter:
        def __init__(self, api_key=None, team_id=None):
            pass

        async def _resolve_label_ids(self, names):
            return ["l1"]

        async def get_issue(self, issue_id):
            return {"identifier": issue_id, "description": "CVE-2024-0001"}

        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            return None

        @staticmethod
        def extract_cve_ids(text):
            return ["CVE-2024-0001"]

        @staticmethod
        def parse_vat_block_from_text(text):
            return None

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _Adapter)
    monkeypatch.setattr(watched_label_inject, "get_labels", _labels)
    monkeypatch.setattr(watched_label_inject, "get_tracker_issue_template", _template)
    monkeypatch.setattr(watched_label_inject, "get_linear_credentials", _creds)
    monkeypatch.setattr(
        watched_label_inject,
        "get_settings",
        lambda: SimpleNamespace(linear_reinject_on_removal=True),
    )

    data = {"issue": {"identifier": "VAT-1", "labelIds": ["l1"]}}
    out = await watched_label_inject.handle_issue_label_update(
        db=SimpleNamespace(),
        data=data,
        updated_from={"labelIds": []},
    )
    assert out["injected"] is True

    reinject = await watched_label_inject.handle_template_reinject(
        db=SimpleNamespace(),
        adapter=_Adapter(),
        issue_obj={"identifier": "VAT-2"},
        issue_id="VAT-2",
        new_description="No template here",
    )
    assert reinject["reinjected"] is True


@pytest.mark.asyncio
async def test_linear_parsed_service_apply_and_post(monkeypatch):
    processed = AsyncMock()
    monkeypatch.setattr(linear_parsed_service, "record_webhook_processed", processed)
    monkeypatch.setattr(
        linear_parsed_service,
        "find_finding_by_linear_issue_id_or_uuid",
        AsyncMock(return_value=None),
    )

    class _Result:
        def __init__(self, finding):
            self._finding = finding

        def scalar_one_or_none(self):
            return self._finding

    db = SimpleNamespace(execute=AsyncMock(side_effect=[_Result(None), _Result(None)]))
    out = await linear_parsed_service.apply_vat_parsed_update(
        db,
        parsed={"cve_id": "CVE-1", "status": "Open", "justification": "j"},
        issue_id="VAT-1",
        issue_uuid="uuid",
        idempotency_key="id1",
        event_name="Comment.create",
        data={},
    )
    assert out["finding"] is None

    fake_finding = SimpleNamespace(id="f-1")
    monkeypatch.setattr(
        linear_parsed_service,
        "find_finding_by_linear_issue_id_or_uuid",
        AsyncMock(return_value=fake_finding),
    )
    monkeypatch.setattr(
        "app.services.findings_service.update_finding",
        AsyncMock(),
    )
    monkeypatch.setitem(
        __import__("app.adapters.registry", fromlist=["TRACKER_ADAPTER_REGISTRY"]).TRACKER_ADAPTER_REGISTRY,
        "linear",
        type("Adapter", (), {"get_capabilities": lambda self: TrackerAdapterCapabilities(supports_inbound_sync=True)}),
    )
    out2 = await linear_parsed_service.apply_vat_parsed_update(
        db,
        parsed={"cve_id": "CVE-1", "status": "Open", "justification": "j"},
        issue_id="VAT-1",
        issue_uuid="uuid",
        idempotency_key="id2",
        event_name="Comment.create",
        data={},
    )
    assert out2["finding_id"] == "f-1"

    adapter = SimpleNamespace(
        format_canonical_block=lambda *args, **kwargs: "[VAT]",
        post_comment=AsyncMock(),
    )
    monkeypatch.setattr(
        linear_parsed_service,
        "get_settings",
        lambda: SimpleNamespace(linear_post_canonical_on_parse=True),
    )
    await linear_parsed_service.post_canonical_if_enabled(
        adapter,
        "VAT-1",
        {"cve_id": "CVE-1", "status": "Open", "justification": "why"},
    )
    assert adapter.post_comment.await_count == 1


@pytest.mark.asyncio
async def test_linear_poll_service_happy_and_error(monkeypatch):
    async def _creds(_db):
        return ("api", "team", None)

    async def _tracked(_db):
        return [("VAT-1", "uuid-1")]

    class _Adapter:
        def __init__(self, api_key=None, team_id=None):
            pass

        async def list_issues_by_ids(self, uuids, include_comments=True, comments_per_issue=50):
            return [
                {
                    "identifier": "VAT-1",
                    "id": "uuid-1",
                    "title": "Issue",
                    "description": "contains [VAT]",
                    "comments": {"nodes": [{"id": "c1", "body": "b", "createdAt": "now"}]},
                }
            ]

        async def get_issue_with_comments(self, issue_id, first=50):
            return None

        @staticmethod
        def parse_vat_block_from_text(text, cve_id_hint=None):
            return {"cve_id": "CVE-1", "status": "Open", "justification": "x"}

        def to_vat_comment_update(self, payload, issue_body_hint=""):
            return SimpleNamespace(
                cve_id="CVE-1",
                status="Open",
                justification="x",
                compensating_controls="",
            )

    monkeypatch.setattr(linear_poll_service, "get_linear_credentials", _creds)
    monkeypatch.setattr(linear_poll_service, "get_all_linear_tracker_issue_ids", _tracked)
    monkeypatch.setattr(linear_poll_service, "LinearAdapter", _Adapter)
    monkeypatch.setattr(linear_poll_service, "is_duplicate_webhook", AsyncMock(return_value=False))
    monkeypatch.setattr(linear_poll_service, "claim_webhook", AsyncMock(return_value=True))
    monkeypatch.setattr(linear_poll_service, "apply_vat_parsed_update", AsyncMock(return_value={"finding_id": "f1"}))
    monkeypatch.setattr(linear_poll_service, "post_canonical_if_enabled", AsyncMock())
    monkeypatch.setattr(
        linear_poll_service,
        "get_settings",
        lambda: SimpleNamespace(linear_poll_enabled=True),
    )
    db = SimpleNamespace(commit=AsyncMock())
    out = await linear_poll_service.poll_linear_for_updates(db)
    assert out["issues_fetched"] == 1
    assert out["comments_processed"] == 1
    assert out["descriptions_processed"] == 1

    class _BadAdapter(_Adapter):
        async def list_issues_by_ids(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(linear_poll_service, "LinearAdapter", _BadAdapter)
    out2 = await linear_poll_service.poll_linear_for_updates(db)
    assert out2["errors"]


@pytest.mark.asyncio
async def test_audit_tasks_and_sync_tasks_runners(monkeypatch):
    class _Engine:
        async def dispose(self):
            return None

    class _Ctx:
        def __init__(self, db):
            self._db = db

        async def __aenter__(self):
            return self._db

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Factory:
        def __init__(self, db):
            self._db = db

        def __call__(self):
            return _Ctx(self._db)

    cp = SimpleNamespace(
        checkpoint_date="2026-01-01",
        retention_class="standard",
        event_count=10,
        anchor_hash="hash",
    )
    db = SimpleNamespace(commit=AsyncMock())
    monkeypatch.setattr(audit_tasks, "get_settings", lambda: SimpleNamespace(audit_daily_checkpoint_enabled=True, audit_checkpoint_retention_class="standard", database_url="sqlite+aiosqlite://"))
    monkeypatch.setattr(audit_tasks, "create_async_engine", lambda url: _Engine())
    monkeypatch.setattr(audit_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(db))
    monkeypatch.setattr(audit_tasks, "create_daily_checkpoint", AsyncMock(return_value=cp))
    out = await audit_tasks._run_daily_checkpoint()
    assert out["event_count"] == 10

    monkeypatch.setattr(sync_tasks, "get_settings", lambda: SimpleNamespace(linear_poll_enabled=True, database_url="sqlite+aiosqlite://", celery_worker_concurrency=2))
    monkeypatch.setattr(sync_tasks, "create_async_engine", lambda url: _Engine())
    sdb = SimpleNamespace(commit=AsyncMock())
    monkeypatch.setattr(sync_tasks, "async_sessionmaker", lambda *args, **kwargs: _Factory(sdb))
    monkeypatch.setattr(sync_tasks, "poll_linear_for_updates", AsyncMock(return_value={"issues_fetched": 0, "comments_processed": 0, "descriptions_processed": 0, "errors": []}))
    assert await sync_tasks._run_linear_poll(force=True) == {"issues_fetched": 0, "comments_processed": 0, "descriptions_processed": 0, "errors": []}

    monkeypatch.setattr(sync_tasks, "unlink_deleted_linear_issues", AsyncMock(return_value=1))
    monkeypatch.setattr(sync_tasks, "link_linear_issues_to_findings", AsyncMock(return_value={"linked": 1, "fetched": 2}))
    monkeypatch.setattr(sync_tasks, "backfill_tracker_corrections", AsyncMock(return_value=1))
    monkeypatch.setattr(sync_tasks, "backfill_unsynced_findings", AsyncMock(return_value=1))
    monkeypatch.setattr(sync_tasks, "process_pending_sync_events", AsyncMock(return_value=2))
    monkeypatch.setattr(sync_tasks, "_run_sync_batch", AsyncMock(return_value=1))
    monkeypatch.setattr("app.api.settings.get_tracker_key", AsyncMock(return_value="linear"))
    monkeypatch.setattr("app.api.settings.get_tracker_push_mode", AsyncMock(return_value="groups"))
    monkeypatch.setattr(
        "app.services.credential_resolver.SettingsCredentialResolver",
        lambda: SimpleNamespace(get_tracker_credentials=AsyncMock(return_value={"api_key": "k", "team_id": "t"})),
    )
    out2 = await sync_tasks._run_sync_worker(limit=4, backfill_limit=2, corrections_limit=2, parallel_batches=2)
    assert out2["processed"] >= 2
    assert out2["linked"] == 1
