#!/usr/bin/env -S uv run python
"""
Fetch Aikido issues/export schema. Run in container with Aikido secrets:
  docker compose exec backend uv run python scripts/fetch_aikido_schema.py

Credentials from: VAT_AIKIDO_* env vars, or Settings DB (aikido_credentials).
"""

import asyncio
import json
import os
import sys

# Add app to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.adapters.aikido import fetch_aikido_issues
from app.core.database import async_session
from app.api.settings import get_aikido_credentials


async def get_creds():
    """Get Aikido credentials from env or DB."""
    client_id = os.environ.get("VAT_AIKIDO_CLIENT_ID")
    client_secret = os.environ.get("VAT_AIKIDO_CLIENT_SECRET")
    if client_id and client_secret:
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "region": os.environ.get("VAT_AIKIDO_REGION", "eu"),
        }
    # Try DB (Settings)
    async with async_session() as db:
        creds = await get_aikido_credentials(db)
    if creds.get("client_id") and creds.get("client_secret"):
        return creds
    return None


async def run():
    creds = await get_creds()
    if not creds or not creds.get("client_id") or not creds.get("client_secret"):
        print("Error: Aikido credentials not found. Set VAT_AIKIDO_CLIENT_ID and VAT_AIKIDO_CLIENT_SECRET in env, or configure in VAT Settings.", file=sys.stderr)
        sys.exit(1)

    issues = await fetch_aikido_issues(credentials=creds)
    if not issues:
        print("No issues returned from Aikido")
        return
    first = issues[0]
    if not isinstance(first, dict):
        print(f"First item is not a dict: {type(first)}")
        return
    # Schema: keys and types
    schema = {}
    for k, v in first.items():
        if v is None:
            schema[k] = "null"
        elif isinstance(v, bool):
            schema[k] = "boolean"
        elif isinstance(v, int):
            schema[k] = "integer"
        elif isinstance(v, float):
            schema[k] = "number"
        elif isinstance(v, str):
            schema[k] = "string"
            if "detect" in k.lower() or "created" in k.lower() or "date" in k.lower() or "at" in k.lower():
                schema[f"{k} (sample)"] = v[:80] if len(v) > 80 else v
        elif isinstance(v, list):
            schema[k] = f"array[{len(v)}]"
            if v and isinstance(v[0], dict):
                schema[f"{k}[0].keys"] = list(v[0].keys())
        elif isinstance(v, dict):
            schema[f"{k}.keys"] = list(v.keys())
        else:
            schema[k] = str(type(v).__name__)
    print("=== Aikido issues/export schema (first issue) ===")
    print(json.dumps(schema, indent=2))
    # Date-related fields explicitly
    date_keys = [k for k in first.keys() if any(d in k.lower() for d in ("detect", "created", "seen", "date", "at", "timestamp"))]
    print("\n=== Date-related fields ===")
    for k in date_keys:
        print(f"  {k}: {repr(first[k])[:100]}")


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
