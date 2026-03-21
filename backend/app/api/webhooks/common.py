"""Shared webhook utilities. PRD §7.3, §8.4."""

import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request


def verify_hmac(
    secret: Optional[str], payload: bytes, signature: Optional[str]
) -> bool:
    """Verify HMAC-SHA256 signature. If secret not configured, skip (operator choice).
    Linear sends raw hex digest; Stripe/GitHub use 'sha256=' prefix. Supports both."""
    if not secret:
        return True
    if not signature:
        return False
    sig = (signature or "").strip()
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected) or hmac.compare_digest(
        sig, f"sha256={expected}"
    )


def verify_replay_timestamp(
    request: Request,
    payload: Optional[dict] = None,
    max_age_sec: int = 30,
    header_names: Optional[list[str]] = None,
    payload_keys: Optional[list[str]] = None,
) -> bool:
    """
    Replay protection: PRD §7.3 — webhook timestamps must be within max_age_sec of receipt.
    Returns True if valid or no timestamp present (allow for backward compat).
    """
    default_headers = ["X-Webhook-Timestamp", "X-Aikido-Webhook-Timestamp"]
    default_payload_keys = [
        "dispatched_at",
        "created_at",
        "timestamp",
        "webhookTimestamp",
    ]

    headers = header_names or default_headers
    keys = payload_keys or default_payload_keys

    ts_val = None
    for h in headers:
        ts_val = request.headers.get(h)
        if ts_val:
            break
    if not ts_val and payload:
        for k in keys:
            ts_val = payload.get(k)
            if ts_val is not None:
                break
    if ts_val:
        try:
            ts = int(ts_val) if isinstance(ts_val, (int, float)) else int(float(ts_val))
            if ts > 1e12:  # milliseconds (e.g. Linear webhookTimestamp)
                ts = ts // 1000
            now = int(datetime.now(timezone.utc).timestamp())
            if abs(now - ts) > max_age_sec:
                return False
        except (ValueError, TypeError):
            return False
    return True
