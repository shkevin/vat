"""Aikido pacing must be shared across processes, and 429s must back all of them off.

The adapter paced with a module-global timestamp, which is per-process. Two
backend replicas plus the celery workers each kept their own, so the real rate
against Aikido was several times the configured gap — the workspace ended up
429-ing on /teams and then on /issues/export mid-sync. Worse, a 429 slept only
in the process that saw it while its siblings kept calling, so the limit never
got a chance to clear.
"""

import inspect
import re

import httpx
import pytest

from app.adapters import aikido as mod


def test_every_429_site_goes_through_the_global_backoff():
    src = inspect.getsource(mod)
    # Retry-After must only be read inside _note_aikido_429; anywhere else means
    # a site that sleeps locally without telling the other processes.
    outside = [
        line.strip()
        for line in src.splitlines()
        if "Retry-After" in line and "retry_after = float" not in line and not line.strip().startswith("#")
    ]
    assert outside == [], f"429 site not using the shared backoff: {outside}"
    assert src.count("_note_aikido_429(") >= 5


def test_pacing_prefers_the_shared_schedule():
    src = inspect.getsource(mod._acquire_rate_limit_slot)
    assert "acquire_gap_slot" in src
    # ...but still paces when there is no Redis, rather than losing it entirely.
    assert "_rate_limit_lock" in src


async def test_note_429_returns_at_least_the_configured_gap(monkeypatch):
    """Retry-After: 1 is common and too optimistic with several processes sharing."""
    noted = {}

    async def _note(key, seconds):
        noted[key] = seconds

    monkeypatch.setattr(mod, "note_upstream_backoff", _note)
    request = httpx.Request("GET", "https://app.aikido.dev/api/public/v1/teams")
    resp = httpx.Response(429, headers={"Retry-After": "1"}, request=request)
    backoff = await mod._note_aikido_429(resp)
    gap_s = mod.get_settings().aikido_request_gap_ms / 1000.0
    assert backoff >= gap_s
    assert noted["aikido"] == backoff


async def test_note_429_survives_a_missing_or_junk_header(monkeypatch):
    async def _note(key, seconds):
        pass

    monkeypatch.setattr(mod, "note_upstream_backoff", _note)
    request = httpx.Request("GET", "https://x/api")
    for headers in ({}, {"Retry-After": "not-a-number"}):
        resp = httpx.Response(429, headers=headers, request=request)
        assert await mod._note_aikido_429(resp) > 0


async def test_falls_back_to_in_process_pacing_without_redis(monkeypatch):
    """No Redis must mean local pacing, never no pacing."""
    async def _no_redis(key, gap_ms):
        return None

    monkeypatch.setattr(mod, "acquire_gap_slot", _no_redis)
    slept = []

    async def _sleep(s):
        slept.append(s)

    monkeypatch.setattr(mod.asyncio, "sleep", _sleep)
    mod._rate_limit_last[0] = mod.time.monotonic()
    await mod._acquire_rate_limit_slot()
    assert slept, "fell through with no pacing at all"
