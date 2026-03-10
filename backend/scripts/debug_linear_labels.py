#!/usr/bin/env python3
"""
Debug Linear labels API. Run in container:
  docker compose exec backend python scripts/debug_linear_labels.py

Uses credentials from DB (Linear settings) or VAT_LINEAR_* env.
"""
import asyncio
import json
import os
import sys

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.api.settings import get_linear_credentials
from app.adapters.linear import LinearAdapter, _resolve_team_uuid


async def _get_db_creds():
    """Get Linear creds from DB."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as db:
        api_key, team_id, _ = await get_linear_credentials(db)
        return api_key, team_id


async def linear_request(api_key: str, query: str, variables: dict) -> dict:
    """POST to Linear GraphQL."""
    url = os.environ.get("VAT_LINEAR_API_URL") or "https://api.linear.app/graphql"
    headers = {"Authorization": api_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json={"query": query, "variables": variables}, headers=headers)
        return resp.json()


async def main():
    api_key, team_id = await _get_db_creds()
    if not api_key or not team_id:
        print("No Linear credentials in DB. Set via VAT UI or VAT_LINEAR_API_KEY + VAT_LINEAR_TEAM_ID env.")
        return

    print(f"team_id config: {team_id!r}")
    adapter = LinearAdapter(api_key=api_key, team_id=team_id)
    team_uuid = await _resolve_team_uuid(adapter)
    print(f"resolved team_uuid: {team_uuid!r}\n")

    # 1. Try team(id).labels (first must be <= 250)
    print("=== Query 1: team(id).labels (first: 250) ===")
    q1 = """
    query TeamLabels($id: String!) {
        team(id: $id) {
            id
            labels(first: 250) {
                nodes { id name }
            }
        }
    }
    """
    r1 = await linear_request(api_key, q1, {"id": team_uuid})
    if "errors" in r1:
        print("ERROR:", json.dumps(r1["errors"], indent=2))
    else:
        team = r1.get("data", {}).get("team")
        if team:
            labels = team.get("labels", {}).get("nodes", [])
            print(f"Found {len(labels)} labels:", [n.get("name") for n in labels])
            for n in labels:
                if n.get("name", "").lower() == "security-bug":
                    print(f"  -> security-bug id: {n.get('id')}")
        else:
            print("team is null:", r1.get("data"))

    # 2. Try issueLabels with team filter (first must be <= 250)
    print("\n=== Query 2: issueLabels(filter: {team: {id: {eq: ...}}}) first: 250 ===")
    q2 = """
    query IssueLabelsByTeam($filter: IssueLabelFilter!) {
        issueLabels(filter: $filter, first: 250) {
            nodes { id name }
        }
    }
    """
    r2 = await linear_request(api_key, q2, {"filter": {"team": {"id": {"eq": team_uuid}}}})
    if "errors" in r2:
        print("ERROR:", json.dumps(r2["errors"], indent=2))
    else:
        nodes = r2.get("data", {}).get("issueLabels", {}).get("nodes", [])
        print(f"Found {len(nodes)} labels:", [n.get("name") for n in nodes])
        for n in nodes:
            if n.get("name", "").lower() == "security-bug":
                print(f"  -> security-bug id: {n.get('id')}")

    # 3. Try issueLabels without filter (all org labels)
    print("\n=== Query 3: issueLabels (no filter, first 20) ===")
    q3 = """
    query {
        issueLabels(first: 20) {
            nodes { id name team { id key } }
        }
    }
    """
    r3 = await linear_request(api_key, q3, {})
    if "errors" in r3:
        print("ERROR:", json.dumps(r3["errors"], indent=2))
    else:
        nodes = r3.get("data", {}).get("issueLabels", {}).get("nodes", [])
        print(f"Found {len(nodes)} labels (showing first 20)")
        for n in nodes[:10]:
            team_info = n.get("team") or {}
            print(f"  {n.get('name')!r} id={n.get('id')} team={team_info.get('key') or team_info.get('id')}")

    # 4. Introspect: what fields does Team have?
    print("\n=== Query 4: Team __schema (fields) ===")
    q4 = """
    query {
        __type(name: "Team") {
            name
            fields {
                name
                type { name kind }
            }
        }
    }
    """
    r4 = await linear_request(api_key, q4, {})
    if "errors" in r4:
        print("ERROR:", json.dumps(r4["errors"], indent=2))
    else:
        t = r4.get("data", {}).get("__type", {})
        fields = t.get("fields", [])
        label_fields = [f for f in fields if "label" in f.get("name", "").lower()]
        print("Team fields containing 'label':", [f["name"] for f in label_fields])


if __name__ == "__main__":
    asyncio.run(main())
