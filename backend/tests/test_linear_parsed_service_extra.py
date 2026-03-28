from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services import linear_parsed_service


@pytest.mark.asyncio
async def test_apply_vat_parsed_update_skips_when_inbound_not_supported(monkeypatch):
    processed = AsyncMock()
    monkeypatch.setattr(linear_parsed_service, "record_webhook_processed", processed)
    monkeypatch.setattr(
        linear_parsed_service,
        "find_finding_by_linear_issue_id_or_uuid",
        AsyncMock(return_value=SimpleNamespace(id="f-1")),
    )

    adapter_cls = type(
        "Adapter",
        (),
        {
            "get_capabilities": lambda self: SimpleNamespace(
                supports_inbound_sync=False
            )
        },
    )
    monkeypatch.setitem(
        __import__(
            "app.adapters.registry", fromlist=["TRACKER_ADAPTER_REGISTRY"]
        ).TRACKER_ADAPTER_REGISTRY,
        "linear",
        adapter_cls,
    )

    out = await linear_parsed_service.apply_vat_parsed_update(
        db=SimpleNamespace(),
        parsed={"cve_id": "CVE-1", "status": "Open", "justification": "j"},
        issue_id="VAT-1",
        issue_uuid="uuid-1",
        idempotency_key="idem-1",
        event_name="Comment.create",
        data={},
    )
    assert out["parsed"] is True
    assert out["skipped"] == "adapter does not support inbound sync"
    assert processed.await_count == 1


@pytest.mark.asyncio
async def test_post_canonical_if_enabled_disabled_and_exception(monkeypatch):
    adapter = SimpleNamespace(
        format_canonical_block=lambda *args, **kwargs: "[VAT]",
        post_comment=AsyncMock(),
    )

    monkeypatch.setattr(
        linear_parsed_service,
        "get_settings",
        lambda: SimpleNamespace(linear_post_canonical_on_parse=False),
    )
    await linear_parsed_service.post_canonical_if_enabled(
        adapter, "VAT-1", {"cve_id": "CVE-1", "status": "Open", "justification": "x"}
    )
    assert adapter.post_comment.await_count == 0

    monkeypatch.setattr(
        linear_parsed_service,
        "get_settings",
        lambda: SimpleNamespace(linear_post_canonical_on_parse=True),
    )

    class _BadAdapter:
        def format_canonical_block(self, *args, **kwargs):
            raise RuntimeError("boom")

        async def post_comment(self, req):
            return None

    # Should swallow exception and not raise.
    await linear_parsed_service.post_canonical_if_enabled(
        _BadAdapter(),
        "VAT-2",
        {"cve_id": "CVE-2", "status": "Open", "justification": "x"},
    )
