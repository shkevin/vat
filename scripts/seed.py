#!/usr/bin/env python3
"""
VAT seed script — loads development/demo data via the API.

Seeds findings, SBOM packages, tenants, and users. Assets are derived from
findings (grouped by image or component).

Requires admin auth. Logs in with POST /api/auth/login (default: admin/admin
from migration 006) to obtain a JWT, then uses Bearer token for seed and
settings endpoints.

Supports two formats:
  - Full seed format (default): Uses POST /api/seed for complete demo data
    (status, attestation, audit, etc.). Requires id, fingerprintId, findingType,
    cveId, severity, status.
  - Canonical ingest format (--ingest): Uses POST /api/ingest for minimal
    payloads. Creates Open findings only; no status/attestation.

Usage:
  # Start backend and PostgreSQL first (e.g. docker compose up -d), then:
  python scripts/seed.py
  # Or with custom API URL:
  VAT_API_URL=http://localhost:8000 python scripts/seed.py
  # Use ingest API (canonical format; findings become Open):
  python scripts/seed.py --ingest
  # Custom credentials (default: admin/admin from migration 006):
  python scripts/seed.py --user admin --password admin
  VAT_SEED_USER=admin VAT_SEED_PASSWORD=admin python scripts/seed.py
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

API_URL = os.environ.get("VAT_API_URL", "http://localhost:8000")
SCRIPT_DIR = Path(__file__).resolve().parent
SEED_DATA_PATH = SCRIPT_DIR / "seed_data.json"


def _get_auth_headers(client: "httpx.Client", user: str, password: str) -> dict[str, str]:
    """Login and return Authorization headers for subsequent requests."""
    base = API_URL.rstrip("/")
    resp = client.post(
        f"{base}/api/auth/login",
        json={"username": user, "password": password},
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("token")
    if not token:
        raise ValueError("Login succeeded but no token returned")
    return {"Authorization": f"Bearer {token}"}


def _component_base(component: str) -> str:
    """Strip version for component_base (matches dedup logic)."""
    if not component:
        return ""
    # Before @ (e.g. log4j-core@2.0) or first word (e.g. runc 1.1.11)
    base = component.split("@")[0].strip()
    return base.split()[0] if base else ""


# VAT uses SCA (Software Composition Analysis), not CVE, for vulnerability findings.
# CVE is an identifier; SCA is the finding classifier (per PRD §5.1.3).
FINDING_TYPE_ALIASES = {"CVE": "SCA"}


def _normalize_finding_type(ft: str | None) -> str:
    """Map legacy/alias finding types to valid VAT FindingType values."""
    if not ft:
        return "SCA"
    return FINDING_TYPE_ALIASES.get(ft, ft)


def _normalize_finding_for_seed(f: dict) -> dict:
    """Ensure finding has fields expected by create_findings_bulk."""
    out = dict(f)
    if "componentBase" not in out and out.get("component"):
        out["componentBase"] = _component_base(str(out["component"]))
    if "findingType" in out:
        out["findingType"] = _normalize_finding_type(out["findingType"])
    return out


def _finding_to_canonical(f: dict) -> dict:
    """Convert full seed finding to canonical ingest format."""
    cvss = f.get("cvss")
    epss = f.get("epss")
    return {
        "cve_id": f.get("cveId") or f.get("cve_id") or "unknown",
        "severity": f.get("severity", "Medium"),
        "description": f.get("description") or "",
        "component": f.get("component"),
        "component_base": f.get("componentBase") or (_component_base(f.get("component", "") or "") or None),
        "image": f.get("image"),
        "title": f.get("title"),
        "finding_type": _normalize_finding_type(f.get("findingType") or f.get("finding_type")),
        "cvss": str(cvss) if cvss is not None else None,
        "epss": str(epss) if epss is not None else None,
        "team": f.get("team"),
        "owner": f.get("owner"),
    }


def derive_assets(findings: list[dict]) -> dict[str, list[dict]]:
    """Derive assets from findings (group by image or component, per frontend logic)."""
    by_asset: dict[str, list[dict]] = {}
    for f in findings:
        image = (f.get("image") or "").strip()
        component = (f.get("component") or "").strip()
        key = image or component or f"unknown-{f.get('id', '')}"
        if key not in by_asset:
            by_asset[key] = []
        by_asset[key].append(f)
    return by_asset


def seed_settings(client: "httpx.Client", settings: dict, headers: dict[str, str]) -> None:
    """Seed settings (sources, tracker, Aikido/Linear credentials) via API."""
    base = API_URL.rstrip("/")
    if settings.get("sources"):
        r = client.put(f"{base}/api/settings/sources", json=settings["sources"], headers=headers)
        r.raise_for_status()
    if settings.get("tracker"):
        r = client.put(f"{base}/api/settings/tracker", json=settings["tracker"], headers=headers)
        r.raise_for_status()
    creds = settings.get("aikido_credentials", {})
    if creds:
        r = client.put(
            f"{base}/api/settings/aikido/credentials",
            json={
                "clientId": creds.get("clientId") or creds.get("client_id") or "",
                "clientSecret": creds.get("clientSecret") or creds.get("client_secret") or "",
                "region": creds.get("region") or "eu",
                "webhookSecret": creds.get("webhookSecret") or creds.get("webhook_secret") or "",
            },
            headers=headers,
        )
        r.raise_for_status()
    creds = settings.get("linear_credentials", {})
    if creds:
        r = client.put(
            f"{base}/api/settings/linear/credentials",
            json={
                "apiKey": creds.get("apiKey") or creds.get("api_key") or "",
                "teamId": creds.get("teamId") or creds.get("team_id") or "",
                "webhookSecret": creds.get("webhookSecret") or creds.get("webhook_secret") or "",
            },
            headers=headers,
        )
        r.raise_for_status()


def summarize(result: dict, findings: list[dict]) -> None:
    """Print summary of what was seeded."""
    status_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    waivers = 0
    in_review = 0
    for f in findings:
        status_counts[f.get("status", "?")] = status_counts.get(f.get("status", "?"), 0) + 1
        type_counts[f.get("findingType", "?")] = type_counts.get(f.get("findingType", "?"), 0) + 1
        if f.get("status") == "Risk Accepted" and f.get("attestation"):
            waivers += 1
        if f.get("status") == "In Review":
            in_review += 1

    print("  Findings:")
    print(f"    By type: {dict(sorted(type_counts.items()))}")
    print(f"    By status: {dict(sorted(status_counts.items()))}")
    print(f"    Waivers (Risk Accepted + attestation): {waivers}")
    print(f"    In Review: {in_review}")
    by_asset = derive_assets(findings)
    print(f"    Assets: {len(by_asset)}")
    top_assets = sorted(by_asset.items(), key=lambda x: -len(x[1]))[:5]
    for asset_id, asset_findings in top_assets:
        print(f"      - {asset_id}: {len(asset_findings)} findings")

    if result.get("sbom_created") or result.get("sbom_updated"):
        print(f"  SBOM: {result.get('sbom_created', 0)} new, {result.get('sbom_updated', 0)} updated packages")
    if result.get("tenants"):
        print(f"  Tenants: {result['tenants']}")
    if result.get("users"):
        print(f"  Users: {result['users']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed VAT with development/demo data")
    parser.add_argument(
        "--ingest",
        action="store_true",
        help="Use POST /api/ingest (canonical format). Findings become Open; no status/attestation.",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=SEED_DATA_PATH,
        help=f"Path to seed data JSON (default: {SEED_DATA_PATH})",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("VAT_SEED_USER", "admin"),
        help="Admin username for login (default: admin from migration 006). Env: VAT_SEED_USER",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("VAT_SEED_PASSWORD", "admin"),
        help="Admin password for login (default: admin from migration 006). Env: VAT_SEED_PASSWORD",
    )
    args = parser.parse_args()

    if httpx is None:
        print("Error: httpx required. Run: pip install httpx")
        return 1

    if not args.data.exists():
        print(f"Error: Seed data not found at {args.data}")
        return 1

    with open(args.data) as f:
        data = json.load(f)

    # Support both { "findings": [...], "sbom": [...], ... } and raw findings array
    if isinstance(data, dict):
        findings = data.get("findings", [])
        sbom = data.get("sbom", [])
        tenants = data.get("tenants", [])
        users = data.get("users", [])
        settings = data.get("settings", {})
    else:
        findings = data
        sbom = []
        tenants = []
        users = []
        settings = {}

    if not findings and not sbom and not tenants and not users and not settings:
        print("Error: No seed data (findings, sbom, tenants, users, or settings)")
        return 1

    # Seed and settings require admin auth; ingest does not
    needs_auth = bool(sbom or tenants or users or settings or (not args.ingest and findings))

    try:
        with httpx.Client(timeout=120.0) as client:
            headers: dict[str, str] = {}
            if needs_auth:
                headers = _get_auth_headers(client, args.user, args.password)

            if args.ingest:
                # Use canonical ingest API for findings (no auth required by default)
                if findings:
                    canonical = [_finding_to_canonical(f) for f in findings]
                    payload = {"source": "seed", "findings": canonical}
                    resp = client.post(f"{API_URL.rstrip('/')}/api/ingest", json=payload)
                    resp.raise_for_status()
                    result = resp.json()
                    print(f"✓ {result.get('message', 'Ingested')}")
                    print(f"  Created: {result.get('created', 0)}, Merged: {result.get('merged', 0)}")
                # Seed sbom, tenants, users via seed API (findings=[] so no replace)
                if sbom or tenants or users:
                    seed_payload = {"findings": [], "sbom": sbom, "tenants": tenants, "users": users}
                    seed_resp = client.post(
                        f"{API_URL.rstrip('/')}/api/seed",
                        json=seed_payload,
                        headers=headers,
                    )
                    seed_resp.raise_for_status()
                    seed_result = seed_resp.json()
                    print(f"✓ {seed_result.get('message', 'Seeded')}")
                    if seed_result.get("sbom_created") or seed_result.get("sbom_updated"):
                        print(f"  SBOM: {seed_result.get('sbom_created', 0)} new, {seed_result.get('sbom_updated', 0)} updated")
                    if seed_result.get("tenants"):
                        print(f"  Tenants: {seed_result['tenants']}")
                    if seed_result.get("users"):
                        print(f"  Users: {seed_result['users']}")
            else:
                # Use full seed API
                payload = {
                    "findings": [_normalize_finding_for_seed(f) for f in findings],
                    "sbom": sbom,
                    "tenants": tenants,
                    "users": users,
                }
                resp = client.post(
                    f"{API_URL.rstrip('/')}/api/seed",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                result = resp.json()
                print(f"✓ {result.get('message', 'Seeded')}")
                print()
                if findings:
                    summarize(result, findings)

            # Seed settings (sources, tracker, Aikido/Linear credentials)
            if settings:
                seed_settings(client, settings, headers)
                print("✓ Settings: sources, tracker, Aikido, Linear")
        return 0
    except httpx.ConnectError:
        print(f"Error: Cannot connect to {API_URL}. Is the backend running?")
        return 1
    except httpx.HTTPStatusError as e:
        detail = ""
        try:
            body = e.response.json()
            detail = body.get("detail", body)
        except Exception:
            detail = e.response.text
        if e.response.status_code == 401:
            print(
                f"Error: Login failed (401). Ensure backend has run migrations (alembic upgrade head) "
                f"so admin user exists. Default: username=admin, password=admin."
            )
        else:
            print(f"Error: API returned {e.response.status_code}: {detail}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
