"""Correlation scoring with explicit asset gate and confidence tiers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.crosswalks import identifiers_crosswalk_match
from app.services.finding_identifiers import list_identifier_facts_for_finding

HIGH_THRESHOLD = 0.85
MEDIUM_THRESHOLD = 0.60


def _norm(value: str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value).strip().lower()
    return ""


def _asset_identity(finding: Any) -> str:
    image = _norm(getattr(finding, "image", None))
    branch = _norm(getattr(finding, "branch", None))
    tag = _norm(getattr(finding, "tag", None))
    component = _norm(getattr(finding, "component", None))
    if image or branch or tag:
        return f"{image}|{branch}|{tag}"
    return component


def _identifiers(finding: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for ns, attr in (
        ("cve_id", "cve_id"),
        ("rule_id", "rule_id"),
        ("stable_rule_key", "stable_rule_key"),
        ("benchmark_family", "benchmark_family"),
        ("control_ref", "control_ref"),
    ):
        value = _norm(getattr(finding, attr, None))
        if value:
            out.append((ns, value))
    return out


async def _identifiers_with_facts(
    db: AsyncSession, finding: Any
) -> list[tuple[str, str]]:
    inline = _identifiers(finding)
    finding_id = _norm(getattr(finding, "id", None))
    if not finding_id:
        return inline
    facts = await list_identifier_facts_for_finding(db, finding_id=finding_id)
    if not facts:
        return inline
    merged: dict[tuple[str, str], bool] = {pair: True for pair in inline}
    for pair in facts:
        merged[(pair[0], pair[1])] = True
    return list(merged.keys())


async def score_finding_pair(
    db: AsyncSession, left: Any, right: Any
) -> dict[str, Any]:
    """
    Score pair and return:
      {score, tier, reasons, evidence}

    Hard gate:
      - mismatched asset identity => score 0, tier low
    """
    reasons: list[str] = []
    evidence: dict[str, Any] = {}
    left_asset = _asset_identity(left)
    right_asset = _asset_identity(right)
    left_key = _norm(getattr(left, "correlation_key", None))
    right_key = _norm(getattr(right, "correlation_key", None))
    key_match = bool(left_key and right_key and left_key == right_key)

    if left_asset and right_asset:
        if left_asset != right_asset:
            reasons.append("asset_mismatch")
            return {
                "score": 0.0,
                "tier": "low",
                "reasons": reasons,
                "evidence": evidence,
            }
        reasons.append("asset_match")
        evidence["asset_identity"] = left_asset
    else:
        if key_match:
            reasons.append("asset_missing_but_key_match")
        else:
            reasons.append("asset_missing")
            return {
                "score": 0.0,
                "tier": "low",
                "reasons": reasons,
                "evidence": evidence,
            }

    score = 0.0
    if key_match:
        score += 0.80
        reasons.append("same_correlation_key")

    left_cve = _norm(getattr(left, "cve_id", None))
    right_cve = _norm(getattr(right, "cve_id", None))
    if left_cve and right_cve and left_cve == right_cve:
        score += 0.10
        reasons.append("same_cve")

    left_rule = _norm(getattr(left, "stable_rule_key", None)) or _norm(
        getattr(left, "rule_id", None)
    )
    right_rule = _norm(getattr(right, "stable_rule_key", None)) or _norm(
        getattr(right, "rule_id", None)
    )
    if left_rule and right_rule and left_rule == right_rule:
        score += 0.10
        reasons.append("same_rule")

    left_identifiers = await _identifiers_with_facts(db, left)
    right_identifiers = await _identifiers_with_facts(db, right)
    left_set = set(left_identifiers)
    right_set = set(right_identifiers)
    shared_pairs = list(left_set & right_set)
    if shared_pairs:
        score += 0.10
        reasons.append("shared_identifier_fact")
        evidence["shared_identifier_facts"] = [
            (str(ns), str(val)) for ns, val in shared_pairs[:10]
        ]
    bridges = await identifiers_crosswalk_match(
        db, left=left_identifiers, right=right_identifiers
    )
    if bridges:
        score += 0.10
        reasons.append("crosswalk_bridge")
        evidence["crosswalk_matches"] = bridges[:10]

    score = min(score, 1.0)
    if score >= HIGH_THRESHOLD:
        tier = "high"
    elif score >= MEDIUM_THRESHOLD:
        tier = "medium"
    else:
        tier = "low"
    evidence["score"] = score
    return {"score": score, "tier": tier, "reasons": reasons, "evidence": evidence}

