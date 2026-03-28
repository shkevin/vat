#!/usr/bin/env python3
"""
Read-only regression: verify GET /api/vat-data (or JSON file) findings.groupKey matches
server grouping rules and list multi-suffix patterns.

Usage:
  VAT_URL=http://localhost:8000 VAT_ADMIN_TOKEN=... uv run python scripts/verify_grouping_vat_export.py
  uv run python scripts/verify_grouping_vat_export.py --file /path/to/vat-data.json

Exit 1 if any groupKey mismatch. Multi-suffix groups are printed to stderr (informational).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _add_backend_to_path() -> None:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def main() -> int:
    _add_backend_to_path()
    from app.services.grouping_export_verify import verify_findings_export

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--file",
        type=Path,
        help="Path to JSON with top-level 'findings' array (vat-data shape)",
    )
    p.add_argument(
        "--url",
        default=os.environ.get("VAT_URL", "").strip(),
        help="VAT base URL (default: env VAT_URL)",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("VAT_ADMIN_TOKEN", "").strip(),
        help="Bearer token (default: env VAT_ADMIN_TOKEN)",
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Request full=1 when fetching (larger payload)",
    )
    args = p.parse_args()

    if args.file:
        data = json.loads(args.file.read_text())
    else:
        base = (args.url or "").rstrip("/")
        tok = args.token
        if not base or not tok:
            print(
                "Need --file or VAT_URL + VAT_ADMIN_TOKEN for live GET.",
                file=sys.stderr,
            )
            return 2
        q = "/api/vat-data?include_assets=true&page=1&page_size=20000"
        if args.full:
            q += "&full=1"
        req = urllib.request.Request(
            f"{base}{q}",
            headers={"Authorization": f"Bearer {tok}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code}: {e.read().decode()[:500]}", file=sys.stderr)
            return 2
        except urllib.error.URLError as e:
            print(f"URL error: {e}", file=sys.stderr)
            return 2

    findings = data.get("findings")
    if not isinstance(findings, list):
        print("Payload missing 'findings' array", file=sys.stderr)
        return 2

    errors, multi = verify_findings_export(findings)
    if multi:
        print(
            f"Multi-suffix group prefixes (same list bucket + type key, different tag/branch): {len(multi)}",
            file=sys.stderr,
        )
        for r in multi[:50]:
            print(
                f"  bucket={r['listAssetBucket'][:80]!r} prefix={r['groupPrefix'][:70]!r} "
                f"n={r['suffixCount']}",
                file=sys.stderr,
            )
        if len(multi) > 50:
            print(f"  ... and {len(multi) - 50} more", file=sys.stderr)

    if errors:
        print(f"groupKey mismatches: {len(errors)}", file=sys.stderr)
        for line in errors[:100]:
            print(f"  {line}", file=sys.stderr)
        if len(errors) > 100:
            print(f"  ... and {len(errors) - 100} more", file=sys.stderr)
        return 1

    print(f"OK: {len(findings)} findings, groupKey recomputation matches API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
