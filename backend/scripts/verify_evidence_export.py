#!/usr/bin/env python3
"""Build a compliance export ZIP and verify required artifacts and manifest hashes."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sys
import zipfile

from sqlalchemy import text

from app.core.database import async_session
from app.services.export_service import ExportBundleOptions, build_export_bundle

REQUIRED_SUFFIXES = (
    "evidence-manifest.json",
    "assets-findings.json",
    "findings.csv",
    "waivers.json",
    "waivers.csv",
    "compliance-summary.pdf",
    "executive-summary-yearly.html",
    "sbom-cyclonedx.json",
    "audit-events.json",
    "auditor-workbook.xlsx",
    "stig/README-STIG-Viewer.txt",
)


def _verify_zip(data: bytes) -> None:
    if not data.startswith(b"PK"):
        raise SystemExit("not a ZIP file")
    zf = zipfile.ZipFile(io.BytesIO(data), "r")
    names = zf.namelist()
    roots = {n.split("/")[0] for n in names if "/" in n}
    if len(roots) != 1:
        raise SystemExit(f"expected single top-level folder, got {roots!r}")
    root = roots.pop()
    for suf in REQUIRED_SUFFIXES:
        path = f"{root}/{suf}"
        if path not in names:
            raise SystemExit(f"missing {path}")

    pdf = zf.read(f"{root}/compliance-summary.pdf")
    if pdf[:4] != b"%PDF":
        raise SystemExit("compliance-summary.pdf is not a PDF")

    manifest = json.loads(zf.read(f"{root}/evidence-manifest.json").decode())
    if manifest.get("schemaVersion") != "evidence-v2":
        raise SystemExit("unexpected evidence-manifest schemaVersion")
    by_path = {e["path"]: e for e in manifest.get("files", [])}
    for suf in REQUIRED_SUFFIXES:
        if suf == "evidence-manifest.json":
            continue
        rel = suf
        zpath = f"{root}/{rel}"
        raw = zf.read(zpath)
        entry = by_path.get(rel)
        if not entry:
            raise SystemExit(f"manifest missing entry for {rel}")
        if entry["sha256"] != hashlib.sha256(raw).hexdigest():
            raise SystemExit(f"sha256 mismatch for {rel}")
        if entry["sizeBytes"] != len(raw):
            raise SystemExit(f"sizeBytes mismatch for {rel}")

    print("OK: evidence export verified")
    print(f"  bundle root: {root}/")
    print(f"  files in manifest: {len(manifest.get('files', []))}")
    print(f"  backend version: {manifest.get('vatBackendVersion')}")


async def _run() -> None:
    async with async_session() as db:
        await db.execute(text("SELECT 1"))
        data = await build_export_bundle(
            db,
            tenant_id=None,
            options=ExportBundleOptions(include_audit_events=True),
        )
    _verify_zip(data)


def main() -> None:
    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"SKIP or ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
