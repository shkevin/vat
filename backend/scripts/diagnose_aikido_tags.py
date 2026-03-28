#!/usr/bin/env python3
"""Print tag-related shapes from live Aikido API (issues/export + GET /containers).

Run from ``backend/``:

  uv run python scripts/diagnose_aikido_tags.py

Requires ``VAT_AIKIDO_CLIENT_ID``, ``VAT_AIKIDO_CLIENT_SECRET`` (and optional region).

Use this when the VAT UI shows only ``latest`` but Aikido shows multiple image tags:
if the export omits per-tag fields, VAT cannot invent tags.

For live CycloneDX (``GET .../licenses/export`` and fallback ``POST .../containers/sbom/generate``),
run ``scripts/verify_aikido_sbom_live.py`` (same credentials).
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from typing import Any

from app.adapters.aikido import (
    _collect_container_tags_from_issue,
    aikido_container_list_item_tags,
    fetch_aikido_containers,
    fetch_aikido_issues,
)
from app.core.config import get_settings


def _is_container_issue(issue: dict) -> bool:
    if not isinstance(issue, dict):
        return False
    if issue.get("container_repo_name") or issue.get("containerRepoName"):
        return True
    locs = issue.get("locations") or issue.get("instances") or []
    if isinstance(locs, list) and locs and isinstance(locs[0], dict):
        return "container" in str(locs[0].get("type", "")).lower()
    return False


def _top_level_keys(d: dict) -> list[str]:
    return sorted(str(k) for k in d.keys())


def _summarize_container_issues(issues: list[dict]) -> None:
    container_issues = [i for i in issues if isinstance(i, dict) and _is_container_issue(i)]
    print(f"\n=== Issues export: {len(issues)} total, {len(container_issues)} container-like ===")
    if not container_issues:
        return

    key_counts: Counter[str] = Counter()
    tag_field_samples: dict[str, list[Any]] = {}
    collected_stats: Counter[str] = Counter()
    for issue in container_issues[:50]:
        for k in issue.keys():
            key_counts[str(k)] += 1
        collected = _collect_container_tags_from_issue(issue)
        label = ",".join(collected) if collected else "(none)"
        collected_stats[label] += 1

    interesting = (
        "tag",
        "image_tag",
        "imageTag",
        "container_tag",
        "containerTag",
        "docker_image",
        "instances",
        "locations",
        "affected_images",
        "image_refs",
    )
    for ik in interesting:
        present = sum(1 for i in container_issues[:50] if ik in i and i.get(ik) not in (None, [], {}))
        if present:
            for i in container_issues[:50]:
                if ik in i and i.get(ik) not in (None, [], {}):
                    tag_field_samples.setdefault(ik, []).append(i.get(ik))
                    if len(tag_field_samples[ik]) >= 2:
                        break

    print("Top keys (first 50 container issues):", key_counts.most_common(25))
    print(
        "\nCollected tags via _collect_container_tags_from_issue (first 50 container issues):"
    )
    for k, v in collected_stats.most_common(15):
        print(f"  {v}x  {k[:120]}")
    if tag_field_samples:
        print("\nSample values for interesting fields:")
        for k, vals in tag_field_samples.items():
            print(f"  {k}: {json.dumps(vals, default=str)[:500]}")


def _summarize_containers(containers: list[dict]) -> None:
    print(f"\n=== GET /containers: {len(containers)} rows ===")
    if not containers:
        return
    key_counts: Counter[str] = Counter()
    for c in containers[:80]:
        if isinstance(c, dict):
            for k in c.keys():
                key_counts[str(k)] += 1
    print("Top keys (first 80 rows):", key_counts.most_common(20))

    union_tags: Counter[str] = Counter()
    for c in containers[:80]:
        if not isinstance(c, dict):
            continue
        tl = aikido_container_list_item_tags(c)
        union_tags[len(tl)] += 1
    print("aikido_container_list_item_tags result lengths (0=would default to bootstrap tag):", dict(union_tags))

    for c in containers[:5]:
        if isinstance(c, dict):
            print("\nSample row keys:", _top_level_keys(c))
            print("  parsed tags:", aikido_container_list_item_tags(c))


async def main() -> None:
    s = get_settings()
    if not (s.aikido_client_id and s.aikido_client_secret):
        raise SystemExit(
            "Set VAT_AIKIDO_CLIENT_ID and VAT_AIKIDO_CLIENT_SECRET in the environment."
        )
    creds = {
        "client_id": s.aikido_client_id,
        "client_secret": s.aikido_client_secret,
        "region": s.aikido_region or "eu",
    }
    issues = await fetch_aikido_issues(credentials=creds)
    containers = await fetch_aikido_containers(credentials=creds)
    _summarize_container_issues([i for i in issues if isinstance(i, dict)])
    _summarize_containers([c for c in containers if isinstance(c, dict)])


if __name__ == "__main__":
    asyncio.run(main())
