"""Helpers for scanner and reviewer risk scoring metadata."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from cvss import CVSS3

SOURCE_OWNED_SECTIONS = ("source", "threat", "context")


def clean_risk_scoring(value: dict | None) -> dict | None:
    """Return a shallowly normalized risk scoring dict or None when empty."""
    if not isinstance(value, dict):
        return None
    cleaned = {str(k): v for k, v in value.items() if v not in (None, "", {}, [])}
    return cleaned or None


def merge_source_risk_scoring(
    current: dict | None, incoming: dict | None
) -> dict | None:
    """Merge parser-owned scoring sections without touching reviewer evidence."""
    incoming = clean_risk_scoring(incoming)
    if not incoming:
        return clean_risk_scoring(current)
    merged: dict[str, Any] = deepcopy(current) if isinstance(current, dict) else {}
    for section in SOURCE_OWNED_SECTIONS:
        value = incoming.get(section)
        if isinstance(value, dict) and value:
            existing_section = merged.get(section)
            if isinstance(existing_section, dict):
                merged[section] = {**existing_section, **value}
            else:
                merged[section] = deepcopy(value)
    return clean_risk_scoring(merged)


def merge_environmental_risk_scoring(
    current: dict | None, incoming: dict | None, *, user: str, timestamp: str
) -> dict | None:
    """Merge reviewer-owned environmental scoring while preserving source data."""
    incoming = clean_risk_scoring(incoming)
    if not incoming:
        return clean_risk_scoring(current)
    env = incoming.get("environmental")
    if not isinstance(env, dict):
        return clean_risk_scoring(current)
    merged: dict[str, Any] = deepcopy(current) if isinstance(current, dict) else {}
    existing_env = merged.get("environmental")
    if not isinstance(existing_env, dict):
        existing_env = {}
    incoming_env = dict(env)
    if not incoming_env.get("score") and incoming_env.get("vector"):
        score = environmental_score_from_vector(str(incoming_env["vector"]))
        if score is not None:
            incoming_env["score"] = score
    next_env = {**existing_env, **incoming_env, "updatedBy": user, "updatedAt": timestamp}
    merged["environmental"] = {
        key: value for key, value in next_env.items() if value not in (None, "", {}, [])
    }
    return clean_risk_scoring(merged)


def environmental_score_from_vector(vector: str) -> str | None:
    """Compute CVSS v3 environmental score from a full vector."""
    try:
        score = CVSS3(vector).scores()[2]
    except Exception:
        return None
    return f"{float(score):.1f}"


def score_from_risk_scoring(value: dict | None) -> str | None:
    if not isinstance(value, dict):
        return None
    source = value.get("source")
    if isinstance(source, dict) and source.get("score") not in (None, ""):
        return str(source["score"])
    return None


def epss_from_risk_scoring(value: dict | None) -> str | None:
    if not isinstance(value, dict):
        return None
    threat = value.get("threat")
    if isinstance(threat, dict) and threat.get("epss") not in (None, ""):
        return str(threat["epss"])
    return None
