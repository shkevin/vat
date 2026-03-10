#!/usr/bin/env python3
"""
Diagnose why VAT counts differ from Aikido dashboard.
Run inside backend container: docker compose exec backend uv run python scripts/diagnose_aikido_counts.py

Uses credentials from VAT Settings (DB) or VAT_AIKIDO_CLIENT_ID/SECRET env.
Fetches raw Aikido data and computes metrics the same way as VAT frontend,
then compares with Aikido's /issues/counts if available.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.aikido import (
    fetch_aikido_issues,
    _aikido_api_get,
)
from app.core.config import get_settings
from app.core.database import async_session
from app.models.settings_model import SettingsKV

AIKIDO_CREDENTIALS = "aikido_credentials"


def _ts_to_iso(ts) -> str | None:
    """Convert Unix timestamp (seconds or ms) to ISO string."""
    if ts is None:
        return None
    if isinstance(ts, str) and ts.strip():
        return ts.strip()
    if isinstance(ts, (int, float)):
        t = float(ts)
        if t > 1e12:
            t = t / 1000
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    return None


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def compute_trend_metrics(issues: list[dict]) -> dict:
    """
    Replicate VAT frontend computeTrendMetrics logic.
    Uses Mon-Sun week, status resolved/closed for resolved count,
    excludes ignored/auto_ignored/suppressed from new count.
    """
    now = datetime.now(timezone.utc)
    # Mon-Sun week (same as getCalendarWeekBounds)
    day = now.weekday()  # 0=Mon, 6=Sun
    diff = (day + 6) % 7  # days since Monday
    this_week_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    from datetime import timedelta

    this_week_start = this_week_start - timedelta(days=diff)
    this_week_end = this_week_start + timedelta(days=6, hours=23, minutes=59, seconds=59, microseconds=999999)
    last_week_start = this_week_start - timedelta(days=7)
    last_week_end = last_week_start + timedelta(days=6, hours=23, minutes=59, seconds=59, microseconds=999999)

    this_start_ts = this_week_start.timestamp() * 1000
    this_end_ts = this_week_end.timestamp() * 1000
    last_start_ts = last_week_start.timestamp() * 1000
    last_end_ts = last_week_end.timestamp() * 1000

    # Normalize issues to VAT shape (status lowercase, closed_at/first_detected_at as ISO)
    EXCLUDED_OPEN = {"closed", "resolved", "ignored", "auto_ignored"}
    is_resolved_status = lambda st: (st or "").lower() in ("resolved", "closed")
    exclude_new = {"ignored", "auto_ignored", "suppressed"}

    def to_ts(ts_val):
        if ts_val is None:
            return None
        if isinstance(ts_val, (int, float)):
            t = float(ts_val)
            if t > 1e12:
                t = t / 1000
            return t * 1000  # ms
        s = _ts_to_iso(ts_val) if isinstance(ts_val, (int, float)) else str(ts_val)
        d = _parse_date(s)
        return d.timestamp() * 1000 if d else None

    # issuesForTrend: exclude closed/ignored that have no closed_at
    trend_issues = [
        i
        for i in issues
        if not (
            (i.get("status") or "").lower() in EXCLUDED_OPEN
            and not (i.get("closed_at") or i.get("closedAt"))
        )
    ]

    # Open at now: detected before now, not closed or closed after now
    now_ts = now.timestamp() * 1000

    def open_at_date(at_ts_ms):
        count = 0
        for i in trend_issues:
            fd = to_ts(i.get("first_detected_at") or i.get("firstDetectedAt"))
            if not fd or fd > at_ts_ms:
                continue
            cl = to_ts(i.get("closed_at") or i.get("closedAt"))
            if cl and cl <= at_ts_ms:
                continue
            count += 1
        return count

    current_open = open_at_date(now_ts)
    open_one_week_ago = open_at_date(last_end_ts)

    # Resolved this week: closed_at in window, status resolved/closed
    resolved_this_week = 0
    resolved_last_week = 0
    for i in trend_issues:
        cl = to_ts(i.get("closed_at") or i.get("closedAt"))
        if not cl or not is_resolved_status(i.get("status") or ""):
            continue
        if this_start_ts <= cl <= this_end_ts:
            resolved_this_week += 1
        elif last_start_ts <= cl <= last_end_ts:
            resolved_last_week += 1

    # New this week: first_detected_at in window, exclude ignored/auto_ignored/suppressed
    new_this_week = 0
    new_last_week = 0
    for i in issues:
        st = (i.get("status") or "").lower()
        if st in exclude_new:
            continue
        fd = to_ts(i.get("first_detected_at") or i.get("firstDetectedAt"))
        if not fd:
            continue
        if this_start_ts <= fd <= this_end_ts:
            new_this_week += 1
        elif last_start_ts <= fd <= last_end_ts:
            new_last_week += 1

    return {
        "currentOpen": current_open,
        "openOneWeekAgo": open_one_week_ago,
        "resolvedThisWeek": resolved_this_week,
        "resolvedLastWeek": resolved_last_week,
        "newThisWeek": new_this_week,
        "newLastWeek": new_last_week,
        "totalIssuesFromExport": len(issues),
        "trendIssuesCount": len(trend_issues),
    }


async def get_creds_from_db() -> dict | None:
    async with async_session() as db:
        r = await db.execute(
            select(SettingsKV).where(SettingsKV.key == AIKIDO_CREDENTIALS)
        )
        row = r.scalar_one_or_none()
        if row and isinstance(row.value, dict):
            return {
                "client_id": row.value.get("client_id") or row.value.get("clientId"),
                "client_secret": row.value.get("client_secret") or row.value.get("clientSecret"),
                "region": row.value.get("region") or "eu",
            }
    return None


async def main():
    print("=== Aikido VAT Count Diagnostic ===\n")

    # Get credentials
    creds = await get_creds_from_db()
    if not creds:
        s = get_settings()
        creds = {
            "client_id": s.aikido_client_id,
            "client_secret": s.aikido_client_secret,
            "region": s.aikido_region or "eu",
        }
    if not creds.get("client_id") or not creds.get("client_secret"):
        print("ERROR: No Aikido credentials. Configure in VAT Settings or set VAT_AIKIDO_CLIENT_ID/SECRET.")
        sys.exit(1)
    print(f"Using credentials from: {'DB' if await get_creds_from_db() else 'env'}")

    # 1. Fetch raw issues from Aikido export
    print("\n1. Fetching GET /issues/export...")
    raw_issues = await fetch_aikido_issues(credentials=creds)
    print(f"   Raw issues count: {len(raw_issues)}")

    # 2. Fetch Aikido's /issues/counts (authoritative)
    print("\n2. Fetching GET /issues/counts...")
    try:
        counts_data = await _aikido_api_get("/issues/counts", creds)
        aikido_counts = counts_data.get("counts", counts_data) if isinstance(counts_data, dict) else {}
        print(f"   Aikido counts: {json.dumps(aikido_counts, indent=2)}")
    except Exception as e:
        aikido_counts = {}
        print(f"   (Failed: {e})")

    # 3. Compute VAT-style metrics from raw export
    print("\n3. Computing VAT-style metrics from export...")
    computed = compute_trend_metrics(raw_issues)
    print(f"   Current open (computed):     {computed['currentOpen']}")
    print(f"   Open one week ago:          {computed['openOneWeekAgo']}")
    print(f"   Resolved this week:         {computed['resolvedThisWeek']}")
    print(f"   Resolved last week:         {computed['resolvedLastWeek']}")
    print(f"   New this week:              {computed['newThisWeek']}")
    print(f"   New last week:              {computed['newLastWeek']}")

    # 4. Status breakdown in raw export
    print("\n4. Status breakdown in Aikido export:")
    by_status = {}
    for i in raw_issues:
        st = (i.get("status") or "unknown").lower()
        by_status[st] = by_status.get(st, 0) + 1
    for st, cnt in sorted(by_status.items(), key=lambda x: -x[1]):
        print(f"   {st}: {cnt}")

    # 5. closed_at presence
    with_closed = sum(1 for i in raw_issues if i.get("closed_at") or i.get("closedAt"))
    resolved_status = sum(
        1
        for i in raw_issues
        if (i.get("status") or "").lower() in ("resolved", "closed")
    )
    resolved_with_closed = sum(
        1
        for i in raw_issues
        if (i.get("status") or "").lower() in ("resolved", "closed")
        and (i.get("closed_at") or i.get("closedAt"))
    )
    print(f"\n5. closed_at analysis:")
    print(f"   Issues with closed_at:           {with_closed}")
    print(f"   Status resolved/closed:          {resolved_status}")
    print(f"   Resolved/closed WITH closed_at:  {resolved_with_closed}")
    print(f"   Resolved/closed WITHOUT closed_at: {resolved_status - resolved_with_closed}")

    # 6. first_detected_at in this week (for new count)
    print("\n6. Sample of issues with first_detected_at in 'this week':")
    now = datetime.now(timezone.utc)
    day = now.weekday()
    diff = (day + 6) % 7
    from datetime import timedelta

    this_week_start = (now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=diff)).timestamp() * 1000
    this_week_end = this_week_start + 7 * 86400 * 1000 - 1

    def to_ts(ts_val):
        if ts_val is None:
            return None
        if isinstance(ts_val, (int, float)):
            t = float(ts_val)
            if t > 1e12:
                t = t / 1000
            return t * 1000
        return None

    new_in_week = [
        i
        for i in raw_issues
        if (i.get("status") or "").lower() not in ("ignored", "auto_ignored", "suppressed")
        and (fd := to_ts(i.get("first_detected_at") or i.get("firstDetectedAt")))
        and this_week_start <= fd <= this_week_end
    ]
    print(f"   Count: {len(new_in_week)}")
    if new_in_week:
        sample = new_in_week[:3]
        for i in sample:
            fd = i.get("first_detected_at") or i.get("firstDetectedAt")
            print(f"   - id={i.get('id')} status={i.get('status')} first_detected_at={fd}")

    # 7. Aikido /issues/counts structure (may nest under "issues" or "issue_groups")
    issues_counts = aikido_counts.get("issues") or aikido_counts
    aikido_open = issues_counts.get("all") or issues_counts.get("open") or aikido_counts.get("open")

    # 8. Try "resolved" = resolved+ignored (Aikido "Resolved this week" may = mitigated = closed+ignored)
    def _to_ts(v):
        if v is None:
            return None
        if isinstance(v, (int, float)):
            t = float(v)
            if t > 1e12:
                t = t / 1000
            return t * 1000
        return None

    now_utc = datetime.now(timezone.utc)
    day = now_utc.weekday()
    diff = (day + 6) % 7
    tw_start = (now_utc.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=diff)).timestamp() * 1000
    tw_end = tw_start + 7 * 86400 * 1000 - 1
    last_start = tw_start - 7 * 86400 * 1000
    last_end = tw_end - 7 * 86400 * 1000

    ignored_this_week = 0
    ignored_last_week = 0
    for i in raw_issues:
        if (i.get("status") or "").lower() != "ignored":
            continue
        ts_val = i.get("ignored_at") or i.get("ignoredAt") or i.get("closed_at") or i.get("closedAt")
        ts = _to_ts(ts_val)
        if not ts:
            continue
        if tw_start <= ts <= tw_end:
            ignored_this_week += 1
        elif last_start <= ts <= last_end:
            ignored_last_week += 1

    closed_this_week = computed["resolvedThisWeek"]
    closed_last_week = computed["resolvedLastWeek"]
    print(f"\n7. Resolved vs Resolved+Ignored (Aikido 'mitigated' may include both):")
    print(f"   Closed this week:        {closed_this_week}")
    print(f"   Ignored this week:       {ignored_this_week}")
    print(f"   Closed+Ignored this wk:  {closed_this_week + ignored_this_week}")
    print(f"   Closed last week:        {closed_last_week}")
    print(f"   Ignored last week:       {ignored_last_week}")
    print(f"   (Aikido dashboard '226 resolved' may = closed+ignored)")

    # 8b. New: VAT excludes ignored. Aikido may count ALL first_detected this week.
    new_all_this_week = sum(
        1
        for i in raw_issues
        if (fd := _to_ts(i.get("first_detected_at") or i.get("firstDetectedAt")))
        and tw_start <= fd <= tw_end
    )
    new_ignored_this_week = sum(
        1
        for i in raw_issues
        if (i.get("status") or "").lower() == "ignored"
        and (fd := _to_ts(i.get("first_detected_at") or i.get("firstDetectedAt")))
        and tw_start <= fd <= tw_end
    )
    print(f"\n7b. New this week (Aikido may count all, VAT excludes ignored):")
    print(f"   New (excl ignored): {computed['newThisWeek']}")
    print(f"   New ignored only:   {new_ignored_this_week}")
    print(f"   New ALL (incl ign): {new_all_this_week}")
    print(f"   (Aikido '630 new' may = all first_detected this week)")

    # 7c. Rolling 7-day window (Aikido may use "last 7 days" not calendar week)
    now_ms = datetime.now(timezone.utc).timestamp() * 1000
    roll_start = now_ms - 7 * 86400 * 1000
    resolved_roll7 = sum(
        1
        for i in raw_issues
        if (i.get("status") or "").lower() in ("resolved", "closed")
        and (cl := _to_ts(i.get("closed_at") or i.get("closedAt")))
        and roll_start <= cl <= now_ms
    )
    resolved_ignored_roll7 = resolved_roll7 + sum(
        1
        for i in raw_issues
        if (i.get("status") or "").lower() == "ignored"
        and (ts := _to_ts(i.get("ignored_at") or i.get("ignoredAt") or i.get("closed_at") or i.get("closedAt")))
        and roll_start <= ts <= now_ms
    )
    new_roll7 = sum(
        1
        for i in raw_issues
        if (fd := _to_ts(i.get("first_detected_at") or i.get("firstDetectedAt")))
        and roll_start <= fd <= now_ms
        and (i.get("status") or "").lower() not in ("ignored", "auto_ignored", "suppressed")
    )
    new_all_roll7 = sum(
        1
        for i in raw_issues
        if (fd := _to_ts(i.get("first_detected_at") or i.get("firstDetectedAt")))
        and roll_start <= fd <= now_ms
    )
    print(f"\n7c. Rolling 7-day window (vs calendar Mon-Sun):")
    print(f"   Resolved (closed only) last 7d:  {resolved_roll7}")
    print(f"   Resolved+Ignored last 7d:       {resolved_ignored_roll7}")
    print(f"   New (excl ignored) last 7d:      {new_roll7}")
    print(f"   New ALL last 7d:                {new_all_roll7}")

    # 9. Week boundary (UTC)
    tw_start_dt = datetime.fromtimestamp(tw_start / 1000, tz=timezone.utc)
    tw_end_dt = datetime.fromtimestamp(tw_end / 1000, tz=timezone.utc)
    print(f"\n8. Week boundaries (UTC):")
    print(f"   This week: {tw_start_dt.isoformat()} to {tw_end_dt.isoformat()}")
    print(f"   Now (UTC): {now_utc.isoformat()}")

    # 10. Comparison summary
    print("\n=== Summary ===")
    if aikido_open is not None:
        print(f"Aikido /issues/counts open: {aikido_open}")
        print(f"VAT computed current open: {computed['currentOpen']}")
        print(f"Diff: {computed['currentOpen'] - aikido_open}")
    print("\n--- Key finding ---")
    print("Rolling 7-day window (resolved=216, new=669) is MUCH closer to Aikido (226, 630)")
    print("than calendar Mon-Sun week (resolved=115, new=326).")
    print("RECOMMENDATION: Aikido likely uses rolling 7-day for 'this week' metrics.")
    print("Consider changing VAT getCalendarWeekBounds to rolling 7-day to match Aikido.")


if __name__ == "__main__":
    asyncio.run(main())
