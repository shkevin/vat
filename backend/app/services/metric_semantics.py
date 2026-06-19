"""Canonical metric status semantics shared by dashboard/report backends."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

CLOSED_STATUS_KEYS = {
    "resolved",
    "false positive",
    "duplicate",
    "not applicable",
    "approved",
    "suppressed",
    # Source-native terminal statuses used by report data from integrations.
    "closed",
    "ignored",
    "auto ignored",
}
RISK_ACCEPTED_STATUS_KEY = "risk accepted"


def normalize_metric_status(status: Any) -> str:
    if isinstance(status, Enum):
        raw = str(status.value)
    else:
        raw = str(status or "")
    raw = raw.strip()
    raw = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
    raw = re.sub(r"[_-]+", " ", raw)
    raw = re.sub(r"\s+", " ", raw)
    return raw.lower()


def is_closed_disposition(status: Any) -> bool:
    return normalize_metric_status(status) in CLOSED_STATUS_KEYS


def is_risk_accepted(status: Any) -> bool:
    return normalize_metric_status(status) == RISK_ACCEPTED_STATUS_KEY


def is_verified_disposition(status: Any) -> bool:
    return is_closed_disposition(status)


def is_open_risk(status: Any) -> bool:
    normalized = normalize_metric_status(status)
    return (
        bool(normalized)
        and normalized not in CLOSED_STATUS_KEYS
        and normalized != RISK_ACCEPTED_STATUS_KEY
    )


def _parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_overdue_open_risk(
    status: Any,
    sla_due: str | datetime | None,
    *,
    as_of: str | datetime | None = None,
) -> bool:
    if not is_open_risk(status):
        return False
    due = _parse_dt(sla_due)
    if due is None:
        return False
    now = _parse_dt(as_of) or datetime.now(timezone.utc)
    return due < now
