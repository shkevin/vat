#!/usr/bin/env python3
"""
Diagnose why OCI layout labels fall back to digest instead of image names.
Run from project root: python vat-local-scanner/scripts/diagnose_oci_labels.py <path-to-artifacts>
Example: python vat-local-scanner/scripts/diagnose_oci_labels.py test/artifacts/2026-03-08_0429

Use --list-only to only list tar/wrap contents (no extract, fast).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--list-only"]
    list_only = "--list-only" in sys.argv[1:]

    if len(args) < 1:
        print("Usage: diagnose_oci_labels.py [--list-only] <path-to-artifacts>", file=sys.stderr)
        print("  e.g. diagnose_oci_labels.py test/artifacts/2026-03-08_0429", file=sys.stderr)
        return 1

    root = Path(args[0]).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 1

    print("=" * 60)
    print("OCI Label Diagnosis")
    print("=" * 60)
    print(f"Scan path: {root}\n")

    # Find outer tar
    tars = list(root.rglob("*.tar"))
    if not tars:
        print("No .tar files found. Looking for tar in kamiwaza-helm/...")
        helm_dir = root / "kamiwaza-helm"
        if helm_dir.is_dir():
            tars = list(helm_dir.rglob("*.tar"))
    if not tars:
        print("ERROR: No .tar files found. Ensure the artifacts dir contains the bundle tar.")
        return 1

    tar_path = tars[0]
    print(f"Using tar: {tar_path}\n")

    if list_only:
        print("--list-only: listing contents (no full extract)\n")
        code, out, _ = run(["tar", "-tf", str(tar_path)])
        if code != 0:
            return 1
        entries = [e.strip().rstrip("/") for e in out.splitlines() if e.strip()]
        print(f"Outer tar entries ({len(entries)}):")
        for e in entries[:40]:
            print(f"  {e}")
        wrap_entries = [e for e in entries if e.endswith(".wrap")]
        work = Path(tempfile.mkdtemp(prefix="vat-diagnose-"))
        try:
            for we in wrap_entries[:3]:
                run(["tar", "-xf", str(tar_path), "-C", str(work), we], timeout=120)
                wrap_path = work / we
                if wrap_path.exists():
                    code2, out2, _ = run(["tar", "-tzf", str(wrap_path)], timeout=60)
                    if code2 == 0:
                        lines = [l for l in out2.splitlines() if l.strip()][:60]
                        print(f"\n{we} contents ({len(out2.splitlines())} total, first 60):")
                        for l in lines:
                            print(f"  {l}")
                        has_imgpkg = any("images.yml" in l for l in out2.splitlines())
                        print(f"  .imgpkg/images.yml: {'YES' if has_imgpkg else 'NO'}")
                else:
                    print(f"\n{we}: extracted but not found at {wrap_path}")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return 0

    # List tar contents
    code, out, _ = run(["tar", "-tf", str(tar_path)])
    if code != 0:
        print("Failed to list tar contents")
        return 1
    entries = [e.strip().rstrip("/") for e in out.splitlines() if e.strip()]
    print(f"Tar has {len(entries)} entries. Sample:")
    for e in entries[:20]:
        print(f"  {e}")
    wrap_entries = [e for e in entries if e.endswith(".wrap")]
    print(f"\n.wrap files: {wrap_entries}\n")

    work = Path(tempfile.mkdtemp(prefix="vat-diagnose-"))
    try:
        # Extract tar
        code, _, err = run(["tar", "-xf", str(tar_path), "-C", str(work)], timeout=120)
        if code != 0:
            print(f"tar extract failed: {err}")
            return 1

        for wrap_rel in wrap_entries:
            wrap_path = work / wrap_rel
            if not wrap_path.is_file():
                continue
            wrap_name = wrap_path.stem
            print("-" * 60)
            print(f"Wrap: {wrap_name}.wrap")
            print("-" * 60)

            wrap_extract = work / f"wrap-{wrap_name}"
            wrap_extract.mkdir(exist_ok=True)

            # List wrap contents first (fast - no full extract)
            code, list_out, _ = run(["tar", "-tzf", str(wrap_path)], timeout=60)
            if code != 0:
                print(f"  Failed to list wrap contents")
                continue
            wrap_entries_list = [e.strip() for e in list_out.splitlines() if e.strip()]
            print(f"  Wrap has {len(wrap_entries_list)} entries")

            # Extract only metadata files (fast - skips multi-GB blobs)
            imgpkg_entries = [e for e in wrap_entries_list if ".imgpkg/images.yml" in e]
            index_entries = [e for e in wrap_entries_list if "index.json" in e and "blobs" not in e]
            to_extract = imgpkg_entries[:1] + index_entries[:3]  # Small files only
            if to_extract:
                for entry in to_extract:
                    run(["tar", "-xzf", str(wrap_path), "-C", str(wrap_extract), entry], timeout=30)
            else:
                # Fallback: full extract (slow for large wraps)
                print("  No metadata files in list; doing minimal extract...")
                code, _, err = run(["tar", "-xzf", str(wrap_path), "-C", str(wrap_extract)], timeout=600)
                if code != 0:
                    print(f"  Failed: {err}")
                    continue

            # 1. Look for .imgpkg/images.yml
            imgpkg_files = list(wrap_extract.rglob(".imgpkg/images.yml"))
            print(f"  .imgpkg/images.yml found: {len(imgpkg_files)}")
            for ip in imgpkg_files[:3]:
                print(f"    {ip.relative_to(wrap_extract)}")
                try:
                    data = yaml.safe_load(ip.read_text()) if yaml else None
                    if data and isinstance(data, dict):
                        images = data.get("images") or []
                        print(f"    ImagesLock has {len(images)} images")
                        for i, img in enumerate(images[:5]):
                            if isinstance(img, dict):
                                ref = img.get("image", "?")
                                ann = img.get("annotations") or {}
                                kbld = ann.get("kbld.carvel.dev/id", "")
                                print(f"      [{i}] image: {ref[:80]}...")
                                if kbld:
                                    print(f"          kbld id: {kbld}")
                except Exception as e:
                    print(f"    Error reading: {e}")

            # 2. Find OCI layouts and check index.json
            oci_layouts = []
            for oci in wrap_extract.rglob("oci-layout"):
                layout_dir = oci.parent
                if (layout_dir / "index.json").exists():
                    oci_layouts.append(layout_dir)
            print(f"\n  OCI layouts found: {len(oci_layouts)}")
            for i, layout_dir in enumerate(oci_layouts[:5]):
                rel = layout_dir.relative_to(wrap_extract)
                print(f"    [{i}] {rel}")
                try:
                    idx = json.loads((layout_dir / "index.json").read_text())
                    manifests = idx.get("manifests") or []
                    for m in manifests[:2]:
                        ann = m.get("annotations") or {}
                        ref = ann.get("org.opencontainers.image.ref.name")
                        print(f"        org.opencontainers.image.ref.name: {ref!r}")
                except Exception as e:
                    print(f"        Error: {e}")

            # 3. Directory structure sample
            print(f"\n  Top-level structure:")
            for p in sorted(wrap_extract.iterdir())[:15]:
                if p.is_dir():
                    sub = list(p.iterdir())[:5] if p.is_dir() else []
                    print(f"    {p.name}/ -> {[x.name for x in sub]}")
                else:
                    print(f"    {p.name}")

            # Only do first wrap with images to save time
            if oci_layouts and wrap_name == "kamiwaza":
                break

    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    print("Summary: Check if .imgpkg/images.yml exists and has image refs,")
    print("        or if OCI index.json has org.opencontainers.image.ref.name.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
