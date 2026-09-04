"""The streamed vat-data body must parse to exactly the old payload.

The endpoint emits findings a batch at a time and strips each batch's array
brackets so the pieces concatenate. Off-by-one in that assembly produces
invalid JSON, which the browser only reports as a parse failure, so pin it here.
"""

import json

import pytest

from app.api.vat_data import stream_vat_data_body


async def _collect(rows, assets, meta, batch_size):
    out = b""
    async for chunk in stream_vat_data_body(rows, assets, meta, batch_size):
        out += chunk
    return out


def _rows(n):
    return [{"id": f"f{i}", "severity": "High", "n": i} for i in range(n)]


@pytest.mark.parametrize(
    "count,batch",
    [
        (0, 3),      # empty
        (1, 3),      # single, smaller than a batch
        (3, 3),      # exactly one batch
        (6, 3),      # exact multiple
        (7, 3),      # trailing partial batch
        (5, 1),      # batch of one
        (4, 100),    # batch larger than the data
    ],
)
async def test_streamed_body_matches_a_single_dump(count, batch):
    rows, assets, meta = _rows(count), [{"id": "a1"}], {"page": 1}
    body = await _collect(rows, assets, meta, batch)
    # Null-valued keys are dropped from findings; everything else is verbatim.
    expected = {
        "findings": [{k: v for k, v in r.items() if v is not None} for r in rows],
        "assets": assets,
        "meta": meta,
    }
    assert json.loads(body) == expected
    # Compact and consistent across batch joins — no stray ", " from json.dumps
    # defaults leaking in on some boundaries but not others.
    assert body == json.dumps(expected, default=str, separators=(",", ":")).encode()


async def test_non_json_native_values_still_encode():
    from datetime import datetime

    rows = [{"id": "f1", "createdAt": datetime(2026, 9, 4, 12, 0, 0)}]
    body = await _collect(rows, [], {}, 2)
    assert json.loads(body)["findings"][0]["createdAt"] == "2026-09-04 12:00:00"


async def test_batches_yield_to_the_event_loop():
    """Each batch must suspend, or the loop still starves during a big encode."""
    import asyncio

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    t = asyncio.create_task(ticker())
    await _collect(_rows(10), [], {}, 1)  # 10 batches
    t.cancel()
    assert ticks >= 10


def test_findings_query_orders_by_a_total_order():
    """created_at alone ties (and is often NULL), so paging needs a tiebreaker.

    Without this the same query returns rows in a different order each call,
    which was verified against the live dataset before the fix.
    """
    from app.services.findings_service import _build_findings_query

    order = [str(c) for c in _build_findings_query()._order_by_clauses]
    assert len(order) == 2, f"expected a tiebreaker, got {order}"
    assert "created_at" in order[0] and "DESC" in order[0].upper()
    assert "findings.id" in order[1]


async def test_null_fields_are_dropped_from_findings():
    """27% of the dashboard payload was keys whose value is null.

    JSON null and an absent key both read as undefined on the client, and
    nothing in the frontend compares a finding field to null or tests for key
    presence — verified before making the change.
    """
    rows = [{"id": "f1", "cveId": "CVE-1", "epss": None, "owner": None, "team": ""}]
    body = await _collect(rows, [], {}, 10)
    f = json.loads(body)["findings"][0]
    assert "epss" not in f and "owner" not in f
    # Falsy-but-not-null values must survive — "" is a real value.
    assert f["team"] == ""
    assert f["id"] == "f1" and f["cveId"] == "CVE-1"


async def test_assets_and_meta_keep_their_nulls():
    """Only findings are stripped; assets are ~1,385 rows and not worth the risk."""
    body = await _collect([], [{"id": "a1", "tag": None}], {"page": None}, 10)
    d = json.loads(body)
    assert d["assets"][0]["tag"] is None
    assert d["meta"]["page"] is None
