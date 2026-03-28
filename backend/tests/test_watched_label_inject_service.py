from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import watched_label_inject


def test_label_extraction_helpers():
    assert watched_label_inject._label_ids_from_issue({"labels": ["l1", {"id": "l2"}]}) == [
        "l1",
        "l2",
    ]
    assert watched_label_inject._label_ids_from_issue({"labels": {"nodes": [{"id": "l3"}]}}) == [
        "l3"
    ]
    assert watched_label_inject._label_ids_from_issue({"labels": "bad"}) == []
    assert watched_label_inject._label_ids_from_updated_from({"labels": ["l1", 2]}) == ["l1"]
    assert watched_label_inject._label_ids_from_updated_from({"labels": "bad"}) == []


@pytest.mark.asyncio
async def test_handle_issue_label_update_guard_paths(monkeypatch):
    async def _creds(_db):
        return ("", "team", None)

    monkeypatch.setattr(watched_label_inject, "get_linear_credentials", _creds)
    out = await watched_label_inject.handle_issue_label_update(
        db=SimpleNamespace(), data={"issue": {}}, updated_from={}
    )
    assert out is None

    async def _creds_ok(_db):
        return ("api", "team", None)

    monkeypatch.setattr(watched_label_inject, "get_linear_credentials", _creds_ok)
    async def _labels_empty(_db):
        return []

    monkeypatch.setattr(watched_label_inject, "get_labels", _labels_empty)
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(), data={"issue": {}}, updated_from={}
        )
        is None
    )

    async def _labels(_db):
        return [{"name": "watched"}]

    monkeypatch.setattr(watched_label_inject, "get_labels", _labels)

    # updated_from lacks label history
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(),
            data={"issue": {"labelIds": ["l1"]}},
            updated_from={},
        )
        is None
    )

    class _Adapter:
        def __init__(self, api_key=None, team_id=None):
            pass

        async def _resolve_label_ids(self, names):
            return ["l1"]

        async def get_issue(self, issue_id):
            return {"identifier": issue_id, "description": ""}

        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            return None

        @staticmethod
        def extract_cve_ids(text):
            return []

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _Adapter)
    monkeypatch.setattr(
        watched_label_inject, "get_tracker_issue_template", lambda _db: "[VAT]"
    )

    # no added labels
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(),
            data={"issue": {"identifier": "VAT-1", "labelIds": ["l1"]}},
            updated_from={"labelIds": ["l1"]},
        )
        is None
    )

    class _AdapterNoWatched(_Adapter):
        async def _resolve_label_ids(self, names):
            return []

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _AdapterNoWatched)
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(),
            data={"issue": {"identifier": "VAT-1", "labelIds": ["l1"]}},
            updated_from={"labelIds": []},
        )
        is None
    )

    class _AdapterNoIntersection(_Adapter):
        async def _resolve_label_ids(self, names):
            return ["l9"]

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _AdapterNoIntersection)
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(),
            data={"issue": {"identifier": "VAT-1", "labelIds": ["l1"]}},
            updated_from={"labelIds": []},
        )
        is None
    )

    # missing issue id
    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _Adapter)
    assert (
        await watched_label_inject.handle_issue_label_update(
            db=SimpleNamespace(),
            data={"issue": {"labelIds": ["l1"]}},
            updated_from={"labelIds": []},
        )
        is None
    )


@pytest.mark.asyncio
async def test_handle_issue_label_update_fetch_and_inject_paths(monkeypatch):
    async def _creds(_db):
        return ("api", "team", None)

    async def _labels(_db):
        return [{"name": "watched"}]

    async def _template(_db):
        return "[VAT]"

    class _Adapter:
        def __init__(self, api_key=None, team_id=None):
            pass

        async def _resolve_label_ids(self, names):
            return ["l1"]

        async def get_issue(self, issue_id):
            return None

        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            return None

        @staticmethod
        def extract_cve_ids(text):
            return ["CVE-1"]

    monkeypatch.setattr(watched_label_inject, "get_linear_credentials", _creds)
    monkeypatch.setattr(watched_label_inject, "get_labels", _labels)
    monkeypatch.setattr(watched_label_inject, "get_tracker_issue_template", _template)
    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _Adapter)

    out_none = await watched_label_inject.handle_issue_label_update(
        db=SimpleNamespace(),
        data={"issue": {"identifier": "VAT-1", "labelIds": ["l1"]}},
        updated_from={"labelIds": []},
    )
    assert out_none is None

    class _AdapterHasBlock(_Adapter):
        async def get_issue(self, issue_id):
            return {"identifier": issue_id, "description": "[VAT]\nstatus: Open"}

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _AdapterHasBlock)
    out_has = await watched_label_inject.handle_issue_label_update(
        db=SimpleNamespace(),
        data={"issue": {"identifier": "VAT-2", "labelIds": ["l1"]}},
        updated_from={"labelIds": []},
    )
    assert out_has == {"injected": False, "reason": "issue already has [VAT] block"}

    class _AdapterInjectFail(_Adapter):
        async def get_issue(self, issue_id):
            return {"identifier": issue_id, "description": "No block"}

        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _AdapterInjectFail)
    out_err = await watched_label_inject.handle_issue_label_update(
        db=SimpleNamespace(),
        data={"issue": {"identifier": "VAT-3", "labelIds": ["l1"]}},
        updated_from={"labelIds": []},
    )
    assert out_err["injected"] is False
    assert "boom" in out_err["error"]


@pytest.mark.asyncio
async def test_handle_template_reinject_paths(monkeypatch):
    class _LinearParseable:
        @staticmethod
        def parse_vat_block_from_text(text):
            return {"ok": True}

        @staticmethod
        def extract_cve_ids(text):
            return ["CVE-9"]

    class _Adapter:
        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            return None

    async def _template(_db):
        return "[VAT]"

    monkeypatch.setattr(watched_label_inject, "get_tracker_issue_template", _template)
    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _LinearParseable)

    monkeypatch.setattr(
        watched_label_inject,
        "get_settings",
        lambda: SimpleNamespace(linear_reinject_on_removal=False),
    )
    assert (
        await watched_label_inject.handle_template_reinject(
            db=SimpleNamespace(),
            adapter=_Adapter(),
            issue_obj={"identifier": "VAT-1"},
            issue_id="VAT-1",
            new_description="x",
        )
        is None
    )

    monkeypatch.setattr(
        watched_label_inject,
        "get_settings",
        lambda: SimpleNamespace(linear_reinject_on_removal=True),
    )
    assert (
        await watched_label_inject.handle_template_reinject(
            db=SimpleNamespace(),
            adapter=_Adapter(),
            issue_obj={"identifier": "VAT-1"},
            issue_id="VAT-1",
            new_description="",
        )
        is None
    )
    assert (
        await watched_label_inject.handle_template_reinject(
            db=SimpleNamespace(),
            adapter=_Adapter(),
            issue_obj={"identifier": "VAT-1"},
            issue_id="VAT-1",
            new_description="[VAT]\nstatus: Open",
        )
        is None
    )

    class _LinearNoParse:
        @staticmethod
        def parse_vat_block_from_text(text):
            return None

        @staticmethod
        def extract_cve_ids(text):
            return ["CVE-9"]

    monkeypatch.setattr(watched_label_inject, "LinearAdapter", _LinearNoParse)

    # minimal structure present: no reinject
    assert (
        await watched_label_inject.handle_template_reinject(
            db=SimpleNamespace(),
            adapter=_Adapter(),
            issue_obj={"identifier": "VAT-1"},
            issue_id="VAT-1",
            new_description="status: open\njustification: x",
        )
        is None
    )

    class _AdapterFail(_Adapter):
        async def inject_vat_template_on_issue(self, issue_id, cve_id, template, reason=None):
            raise RuntimeError("inject-fail")

    out = await watched_label_inject.handle_template_reinject(
        db=SimpleNamespace(),
        adapter=_AdapterFail(),
        issue_obj={"identifier": "VAT-2"},
        issue_id="VAT-2",
        new_description="No vat structure",
    )
    assert out["reinjected"] is False
    assert "inject-fail" in out["error"]
