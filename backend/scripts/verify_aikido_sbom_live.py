#!/usr/bin/env python3
"""Live check: Aikido container SBOM APIs return CycloneDX; VAT parses tag/digest.

- GET ``/containers/{id}/licenses/export`` per container
- Optional (requires write scope): POST ``/containers/sbom/generate``
  https://apidocs.aikido.dev/reference/generatecontainersbom

  uv run python scripts/verify_aikido_sbom_live.py
  uv run python scripts/verify_aikido_sbom_live.py --allow-write-bulk
  uv run python scripts/verify_aikido_sbom_live.py --bulk

Requires ``VAT_AIKIDO_CLIENT_ID`` / ``VAT_AIKIDO_CLIENT_SECRET`` (or ``AIKIDO_*`` aliases) in env
or ``.env`` (repo root then ``backend/.env``, non-empty wins).

Exit 1 if no CycloneDX is parsed; exit 0 if at least one document parses.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


def _load_dotenv_files() -> None:
    """Load repo-root then backend ``.env``, merge so empty lines do not mask real values."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return
    root_env = _BACKEND_ROOT.parent / ".env"
    backend_env = _BACKEND_ROOT / ".env"
    merged: dict[str, str] = {}
    for path in (root_env, backend_env):
        if not path.is_file():
            continue
        for k, v in dotenv_values(path).items():
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            merged[k] = s
    for k, v in merged.items():
        os.environ[k] = v

    # Accept unprefixed Aikido vars if VAT_* not set
    if not (os.environ.get("VAT_AIKIDO_CLIENT_ID") or "").strip():
        for alt in ("AIKIDO_CLIENT_ID", "AIKIDO_OAUTH_CLIENT_ID"):
            if (os.environ.get(alt) or "").strip():
                os.environ["VAT_AIKIDO_CLIENT_ID"] = os.environ[alt].strip()
                break
    if not (os.environ.get("VAT_AIKIDO_CLIENT_SECRET") or "").strip():
        for alt in ("AIKIDO_CLIENT_SECRET", "AIKIDO_OAUTH_CLIENT_SECRET"):
            if (os.environ.get(alt) or "").strip():
                os.environ["VAT_AIKIDO_CLIENT_SECRET"] = os.environ[alt].strip()
                break


_load_dotenv_files()

from app.adapters.aikido import (
    aikido_container_list_item_tags,
    diagnose_aikido_sbom_bulk_generate,
    fetch_aikido_container_licenses_export,
    fetch_aikido_containers,
    fetch_aikido_containers_sbom_bulk_generate,
)
from app.core.config import get_settings
from app.services.aikido_container_sbom_sync import (
    _container_display_fields,
    iter_cyclonedx_from_aikido_bulk_sbom,
)
from app.services.cyclonedx_identity import (
    extract_container_identity_from_cyclonedx,
    unwrap_cyclonedx_document,
)


def _raw_shape_summary(raw: Any) -> str:
    if raw is None:
        return "null"
    if isinstance(raw, dict):
        keys = sorted(str(k) for k in raw.keys())[:12]
        more = len(raw) - len(keys)
        suf = f" (+{more} more)" if more > 0 else ""
        return f"dict keys={keys}{suf}"
    t = type(raw).__name__
    s = str(raw)[:120]
    return f"{t}: {s!r}"


def _tag_aligns_with_list(
    parsed_tag: str | None,
    list_tag: str,
    union_tags: list[str],
) -> tuple[bool, str]:
    if not parsed_tag:
        return False, "sbom_tag_missing"
    if parsed_tag == list_tag:
        return True, "matches_list_tag_field"
    if union_tags and parsed_tag in union_tags:
        return True, "matches_union_tags"
    if list_tag == "latest" and parsed_tag:
        return True, "list_was_latest_sbom_has_tag"
    return False, "mismatch"


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-containers",
        type=int,
        default=50,
        help="Max container rows to probe (default 50)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-container lines even when export is empty",
    )
    parser.add_argument(
        "--bulk",
        action="store_true",
        help="Only call POST /containers/sbom/generate (requires containers:write scope)",
    )
    parser.add_argument(
        "--allow-write-bulk",
        action="store_true",
        help="Enable bulk generate POST fallback (requires containers:write scope)",
    )
    parser.add_argument(
        "--no-bulk-fallback",
        action="store_true",
        help="Do not call bulk generate when every licenses/export response is empty",
    )
    args = parser.parse_args()

    get_settings.cache_clear()
    _load_dotenv_files()
    s = get_settings()
    if not (s.aikido_client_id and s.aikido_client_secret):
        root_e = _BACKEND_ROOT.parent / ".env"
        back_e = _BACKEND_ROOT / ".env"
        print(
            "ERROR: Aikido OAuth client id/secret not found after loading .env.\n"
            "  Expected non-empty VAT_AIKIDO_CLIENT_ID and VAT_AIKIDO_CLIENT_SECRET\n"
            "  (or AIKIDO_CLIENT_ID / AIKIDO_CLIENT_SECRET).\n"
            f"  Checked: {root_e} ({'exists' if root_e.is_file() else 'missing'}), "
            f"{back_e} ({'exists' if back_e.is_file() else 'missing'}).",
            file=sys.stderr,
        )
        return 2

    creds = {
        "client_id": s.aikido_client_id,
        "client_secret": s.aikido_client_secret,
        "region": s.aikido_region or "eu",
    }

    containers = await fetch_aikido_containers(credentials=creds)
    rows = [c for c in containers if isinstance(c, dict) and c.get("id") is not None]
    print(f"Fetched {len(rows)} containers from Aikido (probing up to {args.max_containers}).\n")

    stats = {
        "probed": 0,
        "fetch_empty": 0,
        "csv_exports": 0,
        "not_cyclonedx": 0,
        "cyclonedx_ok": 0,
        "with_digest": 0,
        "with_tag": 0,
        "tag_aligned": 0,
        "bulk_batches": 0,
        "bulk_docs": 0,
    }
    sample = rows[: max(0, args.max_containers)]

    def _report_cdx_for_row(c: dict, cdx: dict, *, via: str) -> None:
        asset_key, cid, list_tag = _container_display_fields(c)
        union_tags = aikido_container_list_item_tags(c)
        ident = extract_container_identity_from_cyclonedx(cdx)
        if ident.digest:
            stats["with_digest"] += 1
        if ident.tag:
            stats["with_tag"] += 1
        ok, reason = _tag_aligns_with_list(ident.tag, list_tag, union_tags)
        if ok:
            stats["tag_aligned"] += 1
        line = (
            f"[{via}] id={cid} asset={asset_key!r} list_tag={list_tag!r} "
            f"union_tags={union_tags!r} -> digest={ident.digest!r} "
            f"sbom_tag={ident.tag!r} stamp_ref={ident.stamp_ref!r} "
            f"display_name={ident.display_name!r} [{reason}]"
        )
        print(line)
        if args.verbose:
            meta = cdx.get("metadata") or {}
            comp = meta.get("component") if isinstance(meta, dict) else None
            if isinstance(comp, dict):
                props = comp.get("properties")
                if isinstance(props, list):
                    pnames = [str(p.get("name")) for p in props if isinstance(p, dict)]
                    print(f"    metadata.component.properties names: {pnames[:20]}")

    if not args.bulk:
        for c in sample:
            stats["probed"] += 1
            _, cid, _ = _container_display_fields(c)
            name = (
                c.get("name")
                or c.get("image")
                or c.get("repository_name")
                or c.get("repositoryName")
                or ""
            )

            raw = await fetch_aikido_container_licenses_export(cid, credentials=creds)
            if raw is None or (isinstance(raw, dict) and not raw):
                stats["fetch_empty"] += 1
                if args.verbose:
                    print(f"  id={cid} name={name!r}: empty_export")
                continue
            if isinstance(raw, str) and raw.lstrip().lower().startswith("package_name,"):
                stats["csv_exports"] += 1

            cdx = unwrap_cyclonedx_document(raw)
            if not cdx:
                stats["not_cyclonedx"] += 1
                if args.verbose or stats["not_cyclonedx"] <= 3:
                    print(
                        f"  id={cid} name={name!r}: not_cyclonedx {_raw_shape_summary(raw)}"
                    )
                continue

            stats["cyclonedx_ok"] += 1
            _report_cdx_for_row(c, cdx, via="licenses/export")

    try_bulk = args.bulk or (
        args.allow_write_bulk
        and not args.no_bulk_fallback
        and stats["cyclonedx_ok"] == 0
        and len(sample) > 0
    )
    if try_bulk:
        if args.bulk:
            stats["probed"] = len(sample)
            print("\n=== POST /containers/sbom/generate (bulk) ===\n")
        else:
            print(
                "\n=== Fallback: POST /containers/sbom/generate "
                "(all licenses/export responses were empty) ===\n"
            )
        ids = [c["id"] for c in sample if c.get("id") is not None]
        raw_bulk = await fetch_aikido_containers_sbom_bulk_generate(ids, credentials=creds)
        if raw_bulk is None:
            print(
                "  bulk: no 2xx JSON response from POST /containers/sbom/generate "
                "(see diagnose below).",
                file=sys.stderr,
            )
            await diagnose_aikido_sbom_bulk_generate(ids, creds, stream=sys.stderr)
        else:
            stats["bulk_batches"] += 1
            if args.verbose:
                print(f"  bulk raw top-level: {_raw_shape_summary(raw_bulk)}")
            pairs = iter_cyclonedx_from_aikido_bulk_sbom(raw_bulk)
            stats["bulk_docs"] = len(pairs)
            chunk_by_id = {str(c.get("id")): c for c in sample if c.get("id") is not None}
            for bid, cdx in pairs:
                stats["cyclonedx_ok"] += 1
                row = None
                if bid is not None and bid in chunk_by_id:
                    row = chunk_by_id[bid]
                elif bid is None and len(pairs) == 1 and len(sample) == 1:
                    row = sample[0]
                if row is None:
                    ident = extract_container_identity_from_cyclonedx(cdx)
                    print(
                        f"[bulk/unmapped] doc_container_id={bid!r} -> "
                        f"digest={ident.digest!r} sbom_tag={ident.tag!r} "
                        f"display_name={ident.display_name!r}"
                    )
                    continue
                _report_cdx_for_row(row, cdx, via="bulk")

    print("\n=== Summary ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    if stats["cyclonedx_ok"] == 0:
        if not (args.bulk or args.allow_write_bulk):
            print(
                "\nFAIL: No CycloneDX documents returned from read API "
                "GET /containers/{id}/licenses/export in this sample.",
                file=sys.stderr,
            )
            print(
                "      Read-only mode is active. If you intentionally want to test "
                "POST /containers/sbom/generate (write scope), rerun with "
                "``--allow-write-bulk``.",
                file=sys.stderr,
            )
        else:
            print(
                "\nFAIL: No CycloneDX documents from licenses/export or bulk generate. "
                "Confirm raw SBOM availability and OAuth scopes.",
                file=sys.stderr,
            )
        return 1

    if stats["with_tag"] == 0:
        print(
            "\nWARN: CycloneDX present but no parsed tag (metadata name / Trivy RepoTag). "
            "Digest-only BOMs still backfill sha256.",
            file=sys.stderr,
        )

    print(
        "\nOK: Live SBOM pull + unwrap + extract_container_identity_from_cyclonedx exercised."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
