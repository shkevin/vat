"""bulk_audit_chain must actually avoid the per-event prev-hash lookup.

Profiling the Aikido bootstrap found 3.25 prev-hash SELECTs and 3.25 audit
INSERTs per finding — 31% of all SQL time — because the same trace_id was
re-read for every event and a flush after each add stopped the inserts
batching. An early version of this optimisation silently dropped the line that
populates the cache, so it still issued every query while looking correct.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.audit_events import (
    _bulk_audit_rows,
    bulk_audit_chain,
    emit_audit_event,
    flush_bulk_audit_events,
)


def _db():
    db = MagicMock()
    db.scalar = AsyncMock(return_value=None)
    db.flush = AsyncMock()
    db.execute = AsyncMock()
    db.add = MagicMock()
    return db


async def _emit(db, trace_id, **kw):
    return await emit_audit_event(
        db, trace_id=trace_id, event_type="t", actor_type="system", **kw
    )


async def test_repeat_traces_are_looked_up_once():
    db = _db()
    async with bulk_audit_chain():
        for _ in range(5):
            await _emit(db, "trace-a")
    # First event seeds from the DB; the rest chain in memory.
    assert db.scalar.await_count == 1, "cache is not being populated"


async def test_each_distinct_trace_is_seeded_once():
    db = _db()
    async with bulk_audit_chain():
        for t in ("a", "b", "c"):
            await _emit(db, t)
            await _emit(db, t)
    assert db.scalar.await_count == 3


async def test_chain_links_events_in_order():
    db = _db()
    async with bulk_audit_chain():
        await _emit(db, "t1")
        await _emit(db, "t1")
        rows = list(_bulk_audit_rows.get())
    assert rows[0]["prev_record_hash"] is None
    # Second event's prev is the first event's hash — the chain is intact.
    assert rows[1]["prev_record_hash"] == rows[0]["record_hash"]


async def test_inserts_are_batched_not_flushed_per_event():
    db = _db()
    async with bulk_audit_chain():
        for i in range(10):
            await _emit(db, f"t{i}")
        assert db.add.call_count == 0, "bulk mode should queue, not ORM-add"
        assert db.flush.await_count == 0, "per-event flush defeats batching"
        n = await flush_bulk_audit_events(db)
    assert n == 10
    assert db.execute.await_count == 1, "expected one executemany"


async def test_outside_the_scope_behaviour_is_unchanged():
    db = _db()
    await _emit(db, "plain")
    assert db.scalar.await_count == 1
    assert db.add.call_count == 1
    assert db.flush.await_count == 1
    assert db.execute.await_count == 0


async def test_scope_is_reset_on_exit_even_after_an_error():
    db = _db()
    with pytest.raises(RuntimeError):
        async with bulk_audit_chain():
            await _emit(db, "t")
            raise RuntimeError("boom")
    assert _bulk_audit_rows.get() is None
