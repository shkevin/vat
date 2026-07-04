"""VAT Local Scanner CLI — vat-scan."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import copy
import fcntl
import gzip
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Iterator
from pathlib import Path

from vat_scanner import __version__
from vat_scanner.config import (
    ALL_SCAN_TYPES,
    DEFAULT_EXCLUDES,
    ScannerConfig,
    find_config_file,
    load_ignore_file,
    load_config_file,
)
from vat_scanner.gating import (
    evaluate_gating,
    extract_gating_findings,
    filter_findings_in_diff,
    get_changed_files,
)
from vat_scanner.scan import run_scan
from vat_scanner.snippet_enrichment import enrich_reports
from vat_scanner.snippets import strip_snippets
from vat_scanner.vat_client import (
    VATClientError,
    cache_key,
    ensure_source,
    get_cached_key,
    ingest_report,
    ingest_openscap_report,
    ingest_openscap_oval_report,
    key_cache_dir,
    source_id_for_parser,
)
from vat_scanner.sarif_output import reports_to_sarif
from vat_scanner.scanners import (
    run_gitleaks,
    run_grype_image_ref,
    run_grype_sbom,
    run_node_oval_cve,
    run_node_stig,
    run_stig_image_ref,
    run_stig_rootfs,
    run_trivy_fs,
    run_trivy_image_ref,
    run_trivy_image_ref_cyclonedx,
)
from vat_scanner.scanners.normalize import normalize_gitleaks, normalize_grype, normalize_trivy
from vat_scanner.archive import extract_archive, is_archive, remove_extracted
from vat_scanner.container_identity import canonical_container_asset, image_digest_from_ref
from vat_scanner.openscap_utils import (
    count_openscap_findings,
    count_openscap_oval_findings,
    save_openscap_xml,
)


def _ingest_headers_for_item(
    bundle_asset: str | None,
    per_item_label: str | None,
    image_ref: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """
    Map bundle vs per-asset mode to VAT ingest headers.

    Returns ``(X-VAT-Asset, X-VAT-Source-Image, X-VAT-Tag)``.

    - ``single`` (bundle): asset = folder/bundle; source_image = container label; tag from CLI only.
    - ``multi``: Aikido-style ``containers/images/<name>`` + image tag from ref/label (scanner-agnostic).
    """
    ba = (bundle_asset or "").strip()
    label = (per_item_label or "").strip()
    if ba:
        return (ba, label or None, None)
    can_img, can_tag = canonical_container_asset(image_ref, label)
    return (can_img, None, can_tag)


def _push_report(
    base_url: str,
    api_key: str,
    parser: str,
    report: object,
    *,
    asset: str | None = None,
    tag: str | None = None,
    scan_id: str | None = None,
    scan_status: str | None = None,
    idempotency_prefix: str | None = None,
) -> list[dict] | None:
    """Push a single report to VAT. Handles openscap/openscap_oval (list of XML) vs JSON.
    asset/tag set X-VAT-Asset/X-VAT-Tag. In multi mode, each list item uses its label as X-VAT-Asset.
    Returns list of ingest responses for openscap/openscap_oval, else None."""
    responses: list[dict] = []

    def _parse_tuple_item(
        item: object,
    ) -> tuple[object, str | None, str | None, str | None]:
        if isinstance(item, tuple) and len(item) >= 4:
            return item[0], item[1], item[2], item[3]
        if isinstance(item, tuple) and len(item) >= 3:
            return item[0], item[1], item[2], None
        if isinstance(item, tuple) and len(item) >= 2:
            return item[0], item[1], None, None
        return item, None, None, None

    if parser == "openscap" and isinstance(report, list):
        for idx, item in enumerate(report):
            xml_content, source_image, image_ref, image_digest = _parse_tuple_item(item)
            if isinstance(xml_content, str) and xml_content.strip():
                eff_asset, eff_src, eff_tag_item = _ingest_headers_for_item(
                    asset, source_image, image_ref
                )
                final_tag = eff_tag_item if eff_tag_item else tag
                idempotency_key = (
                    f"{idempotency_prefix}:{idx}:{source_image or ''}:{image_ref or ''}"
                    if idempotency_prefix
                    else None
                )
                resp = ingest_openscap_report(
                    base_url,
                    api_key,
                    xml_content,
                    asset=eff_asset,
                    tag=final_tag,
                    source_image=eff_src,
                    image_digest=image_digest,
                    scan_id=scan_id,
                    scan_status=scan_status,
                    idempotency_key=idempotency_key,
                )
                responses.append(resp)
    elif parser == "cyclonedx" and isinstance(report, list):
        for idx, item in enumerate(report):
            doc, source_image, image_ref, image_digest = _parse_tuple_item(item)
            if isinstance(doc, dict):
                eff_asset, eff_src, eff_tag_item = _ingest_headers_for_item(
                    asset, source_image, image_ref
                )
                final_tag = eff_tag_item if eff_tag_item else tag
                idempotency_key = (
                    f"{idempotency_prefix}:{idx}:{source_image or ''}:{image_ref or ''}"
                    if idempotency_prefix
                    else None
                )
                resp = ingest_report(
                    base_url,
                    api_key,
                    doc,
                    asset=eff_asset,
                    tag=final_tag,
                    source_image=eff_src,
                    image_digest=image_digest,
                    scan_id=scan_id,
                    scan_status=scan_status,
                    idempotency_key=idempotency_key,
                )
                responses.append(resp)
    elif parser == "openscap_oval" and isinstance(report, list):
        for idx, item in enumerate(report):
            xml_content, source_image, image_ref, image_digest = _parse_tuple_item(item)
            if isinstance(xml_content, str) and xml_content.strip():
                eff_asset, eff_src, eff_tag_item = _ingest_headers_for_item(
                    asset, source_image, image_ref
                )
                final_tag = eff_tag_item if eff_tag_item else tag
                idempotency_key = (
                    f"{idempotency_prefix}:{idx}:{source_image or ''}:{image_ref or ''}"
                    if idempotency_prefix
                    else None
                )
                resp = ingest_openscap_oval_report(
                    base_url,
                    api_key,
                    xml_content,
                    asset=eff_asset,
                    tag=final_tag,
                    source_image=eff_src,
                    image_digest=image_digest,
                    scan_id=scan_id,
                    scan_status=scan_status,
                    idempotency_key=idempotency_key,
                )
                responses.append(resp)
    else:
        ingest_report(
            base_url,
            api_key,
            report,
            asset=asset,
            tag=tag,
            scan_id=scan_id,
            scan_status=scan_status,
            idempotency_key=idempotency_prefix,
        )
        return None
    return responses if responses else None


def _parse_scan_types(s: str) -> list[str]:
    """Parse comma-separated scan types."""
    if not s or not s.strip():
        return list(ALL_SCAN_TYPES)
    raw = [x.strip().lower() for x in s.split(",") if x.strip()]
    valid = [t for t in raw if t in ALL_SCAN_TYPES]
    return valid if valid else list(ALL_SCAN_TYPES)


# Base default when scan types are unspecified. image-grype is recognized (and
# enabled by default in the operator via VAT_INVENTORY_SCAN_TYPES) but kept out
# of the bare-CLI default so a lone `scan-inventory` stays Trivy-only.
INVENTORY_SCAN_TYPES = ("image-sca", "image-sbom")
INVENTORY_SCAN_TYPES_ALL = ("image-sca", "image-grype", "image-sbom")
RUNTIME_SCAN_TYPES = ("image-sca", "image-sbom", "container-stig")
RUNTIME_SCAN_TYPES_ALL = ("image-sca", "image-grype", "image-sbom", "container-stig")
NODE_SCAN_TYPES = ("node-stig", "node-oval-cve")


def _parse_inventory_scan_types(raw: str | None) -> list[str]:
    value = (raw or "").strip()
    if not value:
        value = os.environ.get("VAT_INVENTORY_SCAN_TYPES", "") or ",".join(INVENTORY_SCAN_TYPES)
    requested = [part.strip().lower() for part in value.split(",") if part.strip()]
    if any(part in ("all", "*") for part in requested):
        return list(INVENTORY_SCAN_TYPES_ALL)
    aliases = {
        "trivy": "image-sca",
        "sca": "image-sca",
        "grype": "image-grype",
        "sbom": "image-sbom",
        "cyclonedx": "image-sbom",
    }
    out: list[str] = []
    for part in requested:
        normalized = aliases.get(part, part)
        if normalized in INVENTORY_SCAN_TYPES_ALL and normalized not in out:
            out.append(normalized)
    return out or list(INVENTORY_SCAN_TYPES)


def _parse_node_scan_types(raw: str | None) -> list[str]:
    value = (raw or "").strip()
    if not value:
        value = os.environ.get("VAT_NODE_SCAN_TYPES", "") or ",".join(NODE_SCAN_TYPES)
    requested = [part.strip().lower() for part in value.split(",") if part.strip()]
    if any(part in ("all", "*") for part in requested):
        return list(NODE_SCAN_TYPES)
    aliases = {
        "stig": "node-stig",
        "oval": "node-oval-cve",
        "oval-cve": "node-oval-cve",
        "node-oval": "node-oval-cve",
    }
    out: list[str] = []
    for part in requested:
        normalized = aliases.get(part, part)
        if normalized in NODE_SCAN_TYPES and normalized not in out:
            out.append(normalized)
    return out or list(NODE_SCAN_TYPES)


def _parse_runtime_scan_types(raw: str | None) -> list[str]:
    value = (raw or "").strip()
    if not value:
        value = os.environ.get("VAT_RUNTIME_SCAN_TYPES", "") or ",".join(RUNTIME_SCAN_TYPES)
    requested = [part.strip().lower() for part in value.split(",") if part.strip()]
    if any(part in ("all", "*") for part in requested):
        return list(RUNTIME_SCAN_TYPES_ALL)
    aliases = {
        "trivy": "image-sca",
        "sca": "image-sca",
        "grype": "image-grype",
        "sbom": "image-sbom",
        "cyclonedx": "image-sbom",
        "stig": "container-stig",
        "openscap": "container-stig",
        "container-stig": "container-stig",
    }
    out: list[str] = []
    for part in requested:
        normalized = aliases.get(part, part)
        if normalized in RUNTIME_SCAN_TYPES_ALL and normalized not in out:
            out.append(normalized)
    return out or list(RUNTIME_SCAN_TYPES)


def _node_asset(cluster_name: str, node_name: str) -> str:
    cluster = (cluster_name or "cluster").strip() or "cluster"
    node = (node_name or os.environ.get("NODE_NAME", "") or os.uname().nodename).strip() or "node"
    return f"k8s/{cluster}/node/{node}/host"


def _runtime_asset_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value or "").strip()).strip("-._")
    return slug[:80] or "container"


def _containerd_task_rootfs_path(
    containerd_socket: Path | None,
    containerd_namespace: str,
    container_id: str,
) -> str | None:
    if not containerd_socket or not container_id:
        return None
    task_rootfs = (
        Path(containerd_socket).parent
        / "io.containerd.runtime.v2.task"
        / (containerd_namespace or "k8s.io")
        / container_id
        / "rootfs"
    )
    return str(task_rootfs) if task_rootfs.exists() else None


def _runtime_targets_from_crictl(
    doc: dict,
    cluster_name: str,
    node_name: str,
    *,
    containerd_socket: Path | None = None,
    containerd_namespace: str = "k8s.io",
) -> list[dict]:
    containers = doc.get("containers") if isinstance(doc, dict) else None
    if not isinstance(containers, list):
        return []
    cluster = (cluster_name or "cluster").strip() or "cluster"
    node = (node_name or "unknown-node").strip() or "unknown-node"
    targets: list[dict] = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        image_doc = container.get("image") if isinstance(container.get("image"), dict) else {}
        image = str(
            image_doc.get("userSpecifiedImage")
            or image_doc.get("image")
            or container.get("imageRef")
            or ""
        ).strip()
        if not image:
            continue
        labels = container.get("labels") if isinstance(container.get("labels"), dict) else {}
        metadata = container.get("metadata") if isinstance(container.get("metadata"), dict) else {}
        container_id = str(container.get("id") or "").strip()
        container_name = (
            str(labels.get("io.kubernetes.container.name") or "").strip()
            or str(metadata.get("name") or "").strip()
            or "container"
        )
        namespace = str(labels.get("io.kubernetes.pod.namespace") or "").strip()
        pod_name = str(labels.get("io.kubernetes.pod.name") or "").strip()
        asset = image
        target = {
            "asset": asset,
            "containerId": container_id,
            "containerName": container_name,
            "image": image,
            "nodeName": node,
            "runtimeSource": "containerd",
            "state": str(container.get("state") or "").strip(),
        }
        digest = image_digest_from_ref(str(container.get("imageRef") or image).strip())
        if digest:
            target["imageDigest"] = digest
        if namespace and pod_name:
            target["kubernetes"] = {
                "cluster": cluster,
                "namespace": namespace,
                "podName": pod_name,
                "containerName": container_name,
                "nodeName": node,
            }
        rootfs_path = _containerd_task_rootfs_path(
            containerd_socket,
            containerd_namespace,
            container_id,
        )
        if rootfs_path:
            target["rootfsPath"] = rootfs_path
        targets.append(target)
    return targets


def _preferred_cri_image_ref(image: dict) -> str:
    tags = image.get("repoTags") if isinstance(image.get("repoTags"), list) else []
    digests = image.get("repoDigests") if isinstance(image.get("repoDigests"), list) else []
    for ref in [*tags, *digests]:
        value = str(ref or "").strip()
        if value and value != "<none>:<none>" and not value.startswith("sha256:"):
            return value
    return ""


def _runtime_targets_from_crictl_images(
    doc: dict,
    cluster_name: str,
    node_name: str,
    *,
    referenced_images: set[str] | None = None,
) -> list[dict]:
    images = doc.get("images") if isinstance(doc, dict) else None
    if not isinstance(images, list):
        return []
    referenced = referenced_images or set()
    cluster = (cluster_name or "cluster").strip() or "cluster"
    node = (node_name or "unknown-node").strip() or "unknown-node"
    targets: list[dict] = []
    seen: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            continue
        image_ref = _preferred_cri_image_ref(image)
        if not image_ref or image_ref in referenced or image_ref in seen:
            continue
        seen.add(image_ref)
        image_id = str(image.get("id") or "").strip()
        asset = image_ref
        digest = image_digest_from_ref(
            next(
                (
                    str(ref).strip()
                    for ref in (image.get("repoDigests") or [])
                    if str(ref).strip()
                ),
                image_ref,
            )
        )
        targets.append(
            {
                "asset": asset,
                "containerId": image_id,
                "containerName": image_ref,
                "image": image_ref,
                **({"imageDigest": digest} if digest else {}),
                "nodeName": node,
                "runtimeSource": "containerd",
                "state": "IMAGE_PRESENT",
            }
        )
    return targets


def _runtime_targets_from_docker_containers(
    rows: list[dict],
    cluster_name: str,
    node_name: str,
    *,
    docker_socket: Path | None = None,
    docker_host_root: Path = Path("/host"),
) -> list[dict]:
    cluster = (cluster_name or "cluster").strip() or "cluster"
    node = (node_name or "unknown-node").strip() or "unknown-node"
    targets: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        image = str(row.get("Image") or "").strip()
        if not image:
            continue
        container_id = str(row.get("ID") or "").strip()
        raw_name = str(row.get("Names") or row.get("Names") or "").strip()
        container_name = raw_name.split(",", 1)[0].lstrip("/") or container_id[:12] or "container"
        asset = image
        target = {
            "asset": asset,
            "containerId": container_id,
            "containerName": container_name,
            "image": image,
            "nodeName": node,
            "runtimeSource": "docker",
            "state": str(row.get("State") or row.get("Status") or "").strip(),
        }
        rootfs_path = _docker_container_rootfs_path(
            container_id,
            docker_socket=docker_socket,
            docker_host_root=docker_host_root,
        )
        if rootfs_path:
            target["rootfsPath"] = rootfs_path
        targets.append(target)
    return targets


def _docker_container_rootfs_path(
    container_id: str,
    *,
    docker_socket: Path | None,
    docker_host_root: Path = Path("/host"),
) -> str | None:
    if not container_id or not docker_socket or not Path(docker_socket).exists():
        return None
    try:
        result = subprocess.run(
            ["docker", "-H", f"unix://{docker_socket}", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    try:
        doc = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    container = doc[0] if isinstance(doc, list) and doc else {}
    graph = container.get("GraphDriver") if isinstance(container, dict) else {}
    data = graph.get("Data") if isinstance(graph, dict) else {}
    merged = str(data.get("MergedDir") or "").strip()
    if not merged:
        return None
    direct = Path(merged)
    if _path_exists(direct):
        return str(direct)
    mapped = Path(docker_host_root) / merged.lstrip("/")
    return str(mapped) if _path_exists(mapped) else None


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _docker_image_ref(row: dict) -> str:
    repo = str(row.get("Repository") or "").strip()
    tag = str(row.get("Tag") or "").strip()
    digest = str(row.get("Digest") or "").strip()
    if repo and repo != "<none>" and tag and tag != "<none>":
        return f"{repo}:{tag}"
    if repo and repo != "<none>" and digest and digest != "<none>":
        return f"{repo}@{digest}"
    return ""


def _runtime_targets_from_docker_images(
    rows: list[dict],
    cluster_name: str,
    node_name: str,
    *,
    referenced_images: set[str] | None = None,
) -> list[dict]:
    referenced = referenced_images or set()
    cluster = (cluster_name or "cluster").strip() or "cluster"
    node = (node_name or "unknown-node").strip() or "unknown-node"
    targets: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        image_ref = _docker_image_ref(row)
        if not image_ref or image_ref in referenced or image_ref in seen:
            continue
        seen.add(image_ref)
        image_id = str(row.get("ID") or "").strip()
        asset = image_ref
        digest = image_digest_from_ref(image_ref)
        targets.append(
            {
                "asset": asset,
                "containerId": image_id,
                "containerName": image_ref,
                "image": image_ref,
                **({"imageDigest": digest} if digest else {}),
                "nodeName": node,
                "runtimeSource": "docker",
                "state": "IMAGE_PRESENT",
            }
        )
    return targets


def _merge_scan_cli(cfg: ScannerConfig, args: argparse.Namespace) -> ScannerConfig:
    """Merge CLI args into config."""
    scan_types = _parse_scan_types(getattr(args, "scan_types", "") or "")
    return cfg.merge_cli(
        vat_url=args.vat_url or None,
        api_key=args.api_key or None,
        admin_token=args.admin_token or None,
        asset=args.asset or None,
        asset_mode=getattr(args, "asset_mode", None),
        tag=getattr(args, "tag", None),
        scan_types=scan_types if scan_types else None,
        exclude=args.exclude if args.exclude else None,
        dry_run=args.dry_run,
        gating_mode=args.gating_mode or None,
        fail_on=args.fail_on or None,
        base_commit_id=args.base_commit_id or None,
        head_commit_id=args.head_commit_id or None,
        scan_timeout_ms=args.scan_timeout,
        disable_artifact_scanning=args.disable_artifact_scanning,
        reset_keys=args.reset_keys,
        gating_result_output=args.gating_result_output or None,
        no_snippets=True if getattr(args, "no_snippets", False) else None,
        sarif_output=args.sarif_output if getattr(args, "sarif_output", None) else None,
        temp_dir=args.temp_dir if getattr(args, "temp_dir", None) else None,
        debug=args.debug,
        dev_limit=3 if getattr(args, "dev", False) else None,
        verbose=getattr(args, "verbose", False),
        save_openscap_xml=getattr(args, "save_openscap_xml", None) or None,
    )


def _run_gating(
    reports: dict,
    path: Path,
    cfg: ScannerConfig,
    args: argparse.Namespace,
) -> int:
    """Evaluate gating; write output file; return 1 if should fail."""
    if not cfg.fail_on or not cfg.gating_mode:
        return 0

    findings = extract_gating_findings(reports, path)
    if cfg.gating_mode == "pr" and cfg.base_commit_id and cfg.head_commit_id:
        changed = get_changed_files(path, cfg.base_commit_id, cfg.head_commit_id)
        findings = filter_findings_in_diff(findings, changed)

    should_fail, exceeding = evaluate_gating(findings, cfg.fail_on)

    if args.gating_result_output:
        out_data = {
            "fail": should_fail,
            "fail_on": cfg.fail_on,
            "exceeding_count": len(exceeding),
            "exceeding": [
                {"path": f.get("path"), "severity": f.get("severity"), "parser": f.get("parser")}
                for f in exceeding
            ],
        }
        Path(args.gating_result_output).write_text(json.dumps(out_data, indent=2))

    if should_fail:
        print(f"\nGATING FAILED: {len(exceeding)} finding(s) >= {cfg.fail_on}", file=sys.stderr)
        for f in exceeding[:10]:
            print(f"  {f.get('path')}: {f.get('severity')} ({f.get('parser')})", file=sys.stderr)
        if len(exceeding) > 10:
            print(f"  ... and {len(exceeding) - 10} more", file=sys.stderr)
        return 1
    return 0


def _scan_one_path(
    path: Path,
    cfg: ScannerConfig,
    args: argparse.Namespace,
    on_report=None,
) -> tuple[dict, int]:
    """Scan one path, return (reports, gating_exit_code)."""
    asset_name = cfg.asset or path.name
    print("Scanning:", path, flush=True)
    print("Asset:   ", asset_name, flush=True)
    print("Tag:     ", cfg.tag, flush=True)
    if cfg.scan_types != ALL_SCAN_TYPES:
        print("Types:   ", ",".join(cfg.scan_types), flush=True)
    print(flush=True)

    reports = run_scan(path, cfg, on_report=on_report)
    parsers_run = list(reports.keys())
    for p in parsers_run:
        r = reports[p]
        if p == "trivy":
            count = len(r.get("Results") or [])
            print(f"  {p}: {count} result(s)")
        elif p == "grype":
            count = len(r.get("matches") or [])
            print(f"  {p}: {count} result(s)")
        elif p == "npm_audit":
            count = len(r.get("vulnerabilities") or r.get("advisories") or {})
            print(f"  {p}: {count} result(s)")
        elif p == "pip_audit":
            deps = r if isinstance(r, list) else r.get("dependencies") or []
            count = len(deps)
            print(f"  {p}: {count} result(s)")
        elif p == "semgrep":
            count = len(r.get("results") or [])
            print(f"  {p}: {count} result(s)")
        elif p == "gitleaks":
            count = len(r) if isinstance(r, list) else len(r.get("findings") or r.get("Findings") or [])
            print(f"  {p}: {count} result(s)")
        elif p == "openscap":
            report_count = len(r) if isinstance(r, list) else 0
            finding_count = (
                sum(
                    count_openscap_findings(x[0] if isinstance(x, tuple) else x)
                    for x in (r or [])
                )
                if isinstance(r, list)
                else 0
            )
            if report_count > 0:
                print(f"  {p}: {report_count} report(s), {finding_count} finding(s)")
            else:
                print(f"  {p}: 0 result(s)")
        elif p == "openscap_oval":
            report_count = len(r) if isinstance(r, list) else 0
            finding_count = (
                sum(
                    count_openscap_oval_findings(x[0] if isinstance(x, tuple) else x)
                    for x in (r or [])
                )
                if isinstance(r, list)
                else 0
            )
            if report_count > 0:
                print(f"  {p}: {report_count} report(s), {finding_count} finding(s)")
            else:
                print(f"  {p}: 0 result(s)")
        elif p == "cyclonedx":
            if isinstance(r, list):
                docs = len(r)
                count = 0
                for item in r:
                    doc = item[0] if isinstance(item, tuple) and item else item
                    if isinstance(doc, dict):
                        count += len(doc.get("components") or [])
                print(f"  {p}: {docs} document(s), {count} component(s)")
            else:
                count = len(r.get("components") or []) if isinstance(r, dict) else 0
                print(f"  {p}: {count} component(s)")
        else:
            count = 0
            print(f"  {p}: {count} result(s)")

    # Save OpenSCAP XML for debugging (even in dry-run)
    if cfg.save_openscap_xml:
        save_dir = Path(cfg.save_openscap_xml)
        save_dir.mkdir(parents=True, exist_ok=True)
        for p in ("openscap", "openscap_oval"):
            if p in reports and isinstance(reports[p], list):
                for i, item in enumerate(reports[p]):
                    xml_content = item[0] if isinstance(item, tuple) else item
                    label = item[1] if isinstance(item, tuple) and len(item) > 1 else f"container_{i}"
                    if isinstance(xml_content, str) and xml_content.strip():
                        save_openscap_xml(xml_content, save_dir, p, i, str(label))
        print(f"  OpenSCAP XML saved to {save_dir}", flush=True)

    gating_exit = _run_gating(reports, path, cfg, args)
    return reports, gating_exit


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute scan command. Supports multiple paths for batch scanning."""
    paths = [Path(p).resolve() for p in args.paths]
    for path in paths:
        if not path.is_dir():
            print(f"ERROR: Path is not a directory: {path}", file=sys.stderr)
            return 1

    # Use first path for config discovery
    first_path = paths[0]
    config_path = find_config_file(first_path, getattr(args, "config_path", None))
    if config_path:
        cfg = ScannerConfig.from_file(config_path, first_path)
    else:
        runtime_excludes = list(DEFAULT_EXCLUDES)
        runtime_excludes.extend(load_ignore_file(first_path, include_gitignore=True))
        cfg = ScannerConfig(asset=first_path.name, exclude=list(dict.fromkeys(runtime_excludes)))
    cfg = _merge_scan_cli(cfg, args)

    def _prepare_report_for_push(parser: str, report: object, scan_root: Path, no_snippets: bool) -> object:
        payload = copy.deepcopy(report)
        if no_snippets:
            return strip_snippets(payload)
        report_map = {parser: payload}
        enrich_reports(report_map, scan_root)
        return report_map[parser]

    all_reports: dict[str, dict | list] = {}
    gating_exit = 0
    sarif_paths: list[tuple[dict, str]] = []
    incremental_scan_id = uuid.uuid4().hex if (len(paths) == 1 and not args.dry_run) else None
    source_key_cache: dict[str, str] = {}
    incremental_latest: dict[str, object] = {}

    if not args.dry_run and (not cfg.vat_url or not cfg.admin_token):
        print("\nERROR: Set VAT_URL and VAT_ADMIN_TOKEN to push to VAT.", file=sys.stderr)
        print("  export VAT_URL=https://your-vat.example.com")
        print("  export VAT_ADMIN_TOKEN=<admin API key or JWT from VAT Settings>")
        return 1

    def _resolve_source_key(parser: str) -> str:
        source_id = source_id_for_parser(parser)
        if source_id in source_key_cache:
            return source_key_cache[source_id]
        asset_type = "container" if parser in ("openscap", "openscap_oval") else "package"
        source_id, key = ensure_source(
            cfg.vat_url,
            cfg.admin_token,
            parser,
            create_key=True,
            regenerate_key=cfg.reset_keys,
            asset_type=asset_type,
        )
        if key:
            cache_key(source_id, key)
            source_key_cache[source_id] = key
            return key
        cached = get_cached_key(source_id)
        if cached:
            source_key_cache[source_id] = cached
            return cached
        raise VATClientError(f"{source_id}: no key (create in VAT Settings → Integrations)")

    def _push_single_parser(
        parser: str,
        payload: object,
        path_cfg: ScannerConfig,
        path: Path,
        *,
        scan_status: str | None,
    ) -> None:
        key = _resolve_source_key(parser)
        report_asset = (path_cfg.asset or path.name) if path_cfg.asset_mode != "multi" else None
        idempotency_prefix = None
        if incremental_scan_id:
            idempotency_prefix = (
                f"{incremental_scan_id}:{parser}:{report_asset or 'multi'}:{path_cfg.tag or ''}"
            )
        _push_report(
            cfg.vat_url,
            key,
            parser,
            payload,
            asset=report_asset,
            tag=path_cfg.tag or None,
            scan_id=incremental_scan_id,
            scan_status=scan_status,
            idempotency_prefix=idempotency_prefix,
        )

    for i, path in enumerate(paths):
        if len(paths) > 1:
            # Per-path config: use basename as asset when scanning multiple
            path_cfg = cfg.merge_cli(asset=path.name)
        else:
            path_cfg = cfg

        on_report = None
        if incremental_scan_id and not args.dry_run:
            def _on_report(parser: str, report: dict | list, *, _path_cfg=path_cfg, _path=path):
                payload = _prepare_report_for_push(parser, report, _path, _path_cfg.no_snippets)
                incremental_latest[parser] = payload
                _push_single_parser(parser, payload, _path_cfg, _path, scan_status="running")

            on_report = _on_report

        try:
            reports, gating_exit_path = _scan_one_path(path, path_cfg, args, on_report=on_report)
        except VATClientError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        except RuntimeError as e:
            if incremental_scan_id and incremental_latest:
                for parser, payload in incremental_latest.items():
                    try:
                        _push_single_parser(parser, payload, path_cfg, path, scan_status="failed")
                    except VATClientError:
                        pass
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

        if gating_exit_path != 0:
            gating_exit = 1

        asset_name = path_cfg.asset or path.name
        if getattr(args, "sarif_output", None):
            sarif_paths.append((reports, asset_name))

        if args.dry_run:
            continue

        # Merge or push: for multiple paths, push each separately
        if len(paths) == 1:
            all_reports = reports
        else:
            # Push this path's reports immediately
            if path_cfg.no_snippets:
                reports = {k: strip_snippets(v) for k, v in reports.items()}
            else:
                enrich_reports(reports, path)
            if i == 0:
                print("\nPushing to VAT...")
            try:
                for p in list(reports.keys()):
                    if path_cfg.verbose:
                        print(f"  → Pushing {p}", file=sys.stderr, flush=True)
                    _push_single_parser(
                        p,
                        reports[p],
                        path_cfg,
                        path,
                        scan_status="completed" if incremental_scan_id else None,
                    )
                print(f"  Pushed {asset_name}")
            except VATClientError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 1

        if len(paths) > 1 and i < len(paths) - 1:
            print()

    if args.dry_run:
        print("\nDRY RUN: Skipping push to VAT.")
        return gating_exit

    # Single path: push (or multi-path already pushed above)
    if len(paths) == 1:
        try:
            print("\nPushing to VAT...")
            for p, report in all_reports.items():
                payload = _prepare_report_for_push(p, report, paths[0], cfg.no_snippets)
                _push_single_parser(
                    p,
                    payload,
                    cfg,
                    paths[0],
                    scan_status="completed" if incremental_scan_id else None,
                )
                if not incremental_scan_id:
                    print(f"  {p}: pushed")
        except VATClientError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1

    # SARIF output (single path; for multiple paths, first path only)
    if getattr(args, "sarif_output", None) and sarif_paths:
        reports, asset_name = sarif_paths[0]
        sarif_doc = reports_to_sarif(reports, asset_name)
        Path(args.sarif_output).write_text(json.dumps(sarif_doc, indent=2))
        print(f"\nSARIF output written to {args.sarif_output}")

    asset_names = ", ".join(cfg.asset or p.name for p in paths) if len(paths) > 1 else (cfg.asset or paths[0].name)
    print("\nDone. Asset(s):", asset_names)
    return gating_exit


def cmd_scan_archive(args: argparse.Namespace) -> int:
    """Extract archive(s) to temp, scan, push, then delete extracted tree."""
    import uuid

    archive_paths = [Path(p).resolve() for p in args.archives]
    for ap in archive_paths:
        if not ap.is_file():
            print(f"ERROR: Not a file: {ap}", file=sys.stderr)
            return 1
        if not is_archive(ap):
            print(f"ERROR: Unsupported archive format: {ap.name}", file=sys.stderr)
            return 1

    # Config from first archive's parent or cwd
    first_parent = archive_paths[0].parent
    config_path = find_config_file(first_parent, getattr(args, "config_path", None))
    if config_path:
        cfg = ScannerConfig.from_file(config_path, first_parent)
    else:
        runtime_excludes = list(DEFAULT_EXCLUDES)
        runtime_excludes.extend(load_ignore_file(first_parent, include_gitignore=True))
        cfg = ScannerConfig(asset=archive_paths[0].stem, exclude=list(dict.fromkeys(runtime_excludes)))
    cfg = _merge_scan_cli(cfg, args)

    temp_base = Path(cfg.temp_dir)
    temp_base.mkdir(parents=True, exist_ok=True)
    gating_exit = 0
    sarif_paths: list[tuple[dict, str]] = []

    for i, archive_path in enumerate(archive_paths):
        extract_subdir = temp_base / f"vat-scan-{uuid.uuid4().hex[:12]}"
        extracted_root: Path | None = None
        try:
            print(f"Extracting {archive_path.name} to {extract_subdir}...")
            extracted_root = extract_archive(archive_path, extract_subdir)
            if cfg.verbose:
                print(f"  → Extracted to {extracted_root}", file=sys.stderr, flush=True)
            asset_name = (args.asset if len(archive_paths) == 1 else None) or archive_path.stem
            path_cfg = cfg.merge_cli(asset=asset_name)

            reports, gating_exit_path = _scan_one_path(extracted_root, path_cfg, args)
            if gating_exit_path != 0:
                gating_exit = 1

            if getattr(args, "sarif_output", None):
                sarif_paths.append((reports, asset_name))

            if args.dry_run:
                continue

            if not cfg.vat_url or not cfg.admin_token:
                print("\nERROR: Set VAT_URL and VAT_ADMIN_TOKEN to push to VAT.", file=sys.stderr)
                return 1
            if path_cfg.no_snippets:
                reports = {k: strip_snippets(v) for k, v in reports.items()}
            else:
                enrich_reports(reports, extracted_root)
            if i == 0:
                print("\nPushing to VAT...")
            for p in list(reports.keys()):
                if path_cfg.verbose:
                    print(f"  → Pushing {p}", file=sys.stderr, flush=True)
                source_id, key = ensure_source(
                    cfg.vat_url,
                    cfg.admin_token,
                    p,
                    create_key=True,
                    regenerate_key=cfg.reset_keys,
                    asset_type="package",
                )
                if key:
                    cache_key(source_id, key)
                else:
                    key = get_cached_key(source_id)
                if key and p in reports:
                    responses = _push_report(
                        cfg.vat_url, key, p, reports[p],
                        asset=asset_name if path_cfg.asset_mode != "multi" else None,
                        tag=path_cfg.tag or None,
                    )
                    if responses:
                        if p == "cyclonedx":
                            sbom_created = sum(r.get("sbomCreated", 0) for r in responses)
                            sbom_updated = sum(r.get("sbomUpdated", 0) for r in responses)
                            print(f"  {p}: pushed ({sbom_created} SBOM created, {sbom_updated} SBOM updated)")
                        else:
                            total_created = sum(r.get("created", 0) for r in responses)
                            total_merged = sum(r.get("merged", 0) for r in responses)
                            print(f"  {p}: pushed ({total_created} created, {total_merged} merged)")
            print(f"  Pushed {asset_name}")
        except (ValueError, RuntimeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        except VATClientError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        finally:
            remove_extracted(extract_subdir)

        if i < len(archive_paths) - 1:
            print()

    if args.dry_run:
        print("\nDRY RUN: Skipping push to VAT.")

    if getattr(args, "sarif_output", None) and sarif_paths:
        reports, asset_name = sarif_paths[0]
        sarif_doc = reports_to_sarif(reports, asset_name)
        Path(args.sarif_output).write_text(json.dumps(sarif_doc, indent=2))
        print(f"\nSARIF output written to {args.sarif_output}")

    print("\nDone.")
    return gating_exit


def cmd_scan_image(args: argparse.Namespace) -> int:
    """Scan container image and push to VAT."""
    image_ref = args.image
    import re
    asset_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", image_ref.replace("/", "-").replace(":", "-"))
    if args.asset:
        asset_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", args.asset)

    print("Scanning image:", image_ref)
    print("Asset:       ", asset_name)

    report = run_trivy_image_ref(image_ref, timeout=120)
    if not report:
        print("ERROR: Trivy image scan failed or trivy not found.", file=sys.stderr)
        return 1

    report = normalize_trivy(report, asset_name)
    if getattr(args, "no_snippets", False):
        report = strip_snippets(report)

    if getattr(args, "sarif_output", None):
        sarif_doc = reports_to_sarif({"trivy": report}, asset_name)
        Path(args.sarif_output).write_text(json.dumps(sarif_doc, indent=2))
        print(f"SARIF output written to {args.sarif_output}")

    if args.dry_run:
        count = len(report.get("Results") or [])
        print(f"  trivy: {count} result(s)")
        print("\nDRY RUN: Skipping push to VAT.")
        return 0

    import os
    vat_url = (args.vat_url or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (args.admin_token or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not vat_url or not (api_key or admin_token):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    try:
        key = api_key
        if not key:
            source_id, key = ensure_source(
                vat_url, admin_token, "trivy",
                create_key=True, regenerate_key=args.reset_keys,
                asset_type="container",
            )
            if not key:
                key = get_cached_key(source_id)
            if not key:
                print(f"  {source_id}: no key", file=sys.stderr)
                return 1
            cache_key(source_id, key)
        tag_val = getattr(args, "tag", None)
        image_digest = (
            getattr(args, "image_digest", None)
            or os.environ.get("VAT_SCAN_IMAGE_DIGEST", "")
        ).strip() or None
        import time
        last_error: VATClientError | None = None
        for attempt in range(1, 4):
            try:
                resp = ingest_report(
                    vat_url,
                    key,
                    report,
                    asset=asset_name,
                    tag=tag_val,
                    image_digest=image_digest,
                )
                break
            except VATClientError as e:
                last_error = e
                if attempt == 3:
                    raise
                print(f"  trivy ingest attempt {attempt} failed; retrying...", file=sys.stderr)
                time.sleep(attempt * 2)
        if last_error is not None and "resp" not in locals():
            raise last_error
        print(f"  trivy: {resp}")
    except VATClientError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1

    print("\nDone. Asset:", asset_name)
    return 0


def _image_ref_tag(image_ref: str) -> str | None:
    ref = str(image_ref or "").strip()
    if not ref:
        return None
    has_digest = "@" in ref
    ref_without_digest = ref.split("@", 1)[0]
    last_slash = ref_without_digest.rfind("/")
    last_colon = ref_without_digest.rfind(":")
    if last_colon <= last_slash:
        return None if has_digest else "latest"
    tag = ref_without_digest[last_colon + 1 :].strip()
    return tag or None


def _inventory_target_asset_and_tag(
    target: dict,
    cluster_name: str,
    image_ref: str | None = None,
) -> tuple[str | None, str | None]:
    image = str(image_ref or "").strip()
    if not image:
        return None, None
    asset = image
    tag = _image_ref_tag(image)
    return asset, tag


def _inventory_targets(item: dict) -> list[dict]:
    targets = item.get("targets") if isinstance(item, dict) else None
    if not isinstance(targets, list):
        return []
    return [target for target in targets if isinstance(target, dict)]


def _inventory_pull_secret_refs(item: dict) -> list[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for target in _inventory_targets(item):
        namespace = str(target.get("namespace") or "").strip()
        if not namespace:
            continue
        names = target.get("imagePullSecrets") or target.get("imagePullSecretNames") or []
        if not isinstance(names, list):
            continue
        for name in names:
            secret_name = str(name or "").strip()
            if secret_name:
                refs.add((namespace, secret_name))
    return sorted(refs)


def _inventory_fallback_pull_secret_refs(item: dict) -> list[tuple[str, str]]:
    secret_names = [
        piece.strip()
        for piece in os.environ.get("VAT_INVENTORY_FALLBACK_IMAGE_PULL_SECRET_NAMES", "").split(",")
        if piece.strip()
    ]
    if not secret_names:
        return []

    refs: set[tuple[str, str]] = set()
    for target in _inventory_targets(item):
        namespace = str(target.get("namespace") or "").strip()
        if not namespace:
            continue
        for secret_name in secret_names:
            refs.add((namespace, secret_name))
    return sorted(refs)


def _inventory_default_pull_secret_refs() -> list[tuple[str, str]]:
    raw = os.environ.get("VAT_INVENTORY_IMAGE_PULL_SECRETS", "").strip()
    if not raw:
        return []

    default_namespace = os.environ.get("POD_NAMESPACE", "vat-operator").strip() or "vat-operator"
    refs: set[tuple[str, str]] = set()
    for part in [piece.strip() for piece in raw.split(",") if piece.strip()]:
        if "/" in part:
            namespace, secret_name = part.split("/", 1)
        else:
            namespace, secret_name = default_namespace, part
        namespace = namespace.strip()
        secret_name = secret_name.strip()
        if namespace and secret_name:
            refs.add((namespace, secret_name))
    return sorted(refs)


def _fetch_kubernetes_secret(namespace: str, name: str) -> dict | None:
    host = os.environ.get("VAT_KUBERNETES_API_HOST", "kubernetes.default.svc").strip()
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443").strip() or "443"
    token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if not host or not token_path.exists():
        return None
    token = token_path.read_text(encoding="utf-8").strip()
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/secrets/{name}"
    context = ssl.create_default_context(cafile=str(ca_path)) if ca_path.exists() else ssl.create_default_context()
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"  WARN: unable to read imagePullSecret {namespace}/{name}: {e}", file=sys.stderr)
        return None


def _docker_auths_from_secret(secret: dict | None) -> dict:
    if not isinstance(secret, dict):
        return {}
    data = secret.get("data")
    if not isinstance(data, dict):
        return {}
    encoded = data.get(".dockerconfigjson") or data.get(".dockercfg")
    if not encoded:
        return {}
    try:
        decoded = base64.b64decode(str(encoded)).decode("utf-8")
        doc = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return {}
    if isinstance(doc.get("auths"), dict):
        return doc["auths"]
    if isinstance(doc, dict):
        return doc
    return {}


@contextmanager
def _temporary_registry_auth_config(item: dict, temp_base: Path | None = None) -> Iterator[Path | None]:
    auths: dict = {}
    refs = (
        _inventory_default_pull_secret_refs()
        + _inventory_fallback_pull_secret_refs(item)
        + _inventory_pull_secret_refs(item)
    )
    for namespace, secret_name in refs:
        auths.update(_docker_auths_from_secret(_fetch_kubernetes_secret(namespace, secret_name)))
    if not auths:
        yield None
        return

    parent = Path(temp_base) if temp_base else Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vat-registry-auth-", dir=str(parent)) as auth_dir:
        auth_path = Path(auth_dir)
        (auth_path / "config.json").write_text(json.dumps({"auths": auths}), encoding="utf-8")
        yield auth_path


def _inventory_item_key(item: dict) -> str:
    digest = str(item.get("imageDigest") or "").strip()
    if digest:
        return digest
    return str(item.get("image") or "").strip()


def _inventory_target_signature(target: dict) -> str:
    parts = [
        str(target.get("namespace") or "").strip(),
        str(target.get("kind") or "").strip(),
        str(target.get("name") or "").strip(),
        str(target.get("containerName") or "").strip(),
    ]
    secrets = target.get("imagePullSecrets") or target.get("imagePullSecretNames") or []
    if isinstance(secrets, list):
        secret_part = ",".join(sorted(str(name or "").strip() for name in secrets if str(name or "").strip()))
        if secret_part:
            parts.append(f"pullSecrets={secret_part}")
    return "/".join(parts)


def _inventory_item_signature(item: dict) -> str:
    key = _inventory_item_key(item)
    targets = sorted(
        _inventory_target_signature(target)
        for target in _inventory_targets(item)
    )
    return f"{key}|{','.join(targets)}"


def _load_scan_state(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {"images": {}}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"images": {}}
    if not isinstance(doc, dict):
        return {"images": {}}
    images = doc.get("images")
    if not isinstance(images, dict):
        doc["images"] = {}
    return doc


def _save_scan_state(path: Path | None, state: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _parse_state_time(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _full_rescan_due(state: dict, interval_seconds: int, force: bool) -> bool:
    if force:
        return True
    if interval_seconds <= 0:
        return False
    last_full = _parse_state_time(state.get("lastFullScanAt"))
    if last_full is None:
        return False
    age = datetime.now(timezone.utc) - last_full
    return age.total_seconds() >= interval_seconds


def _k8s_inventory_item_key(item: dict) -> str:
    namespace = str(item.get("namespace") or "").strip()
    kind = str(item.get("kind") or "").strip()
    name = str(item.get("name") or "").strip()
    if namespace:
        return f"{namespace}/{kind}/{name}"
    return f"cluster/{kind}/{name}"


def _k8s_inventory_item_signature(item: dict) -> str:
    resource_version = str(item.get("resourceVersion") or "").strip()
    manifest = str(item.get("manifest") or "")
    digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return f"{resource_version}|{digest}"


def _load_k8s_scan_state(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {"objects": {}}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"objects": {}}
    if not isinstance(doc, dict):
        return {"objects": {}}
    objects = doc.get("objects")
    if not isinstance(objects, dict):
        doc["objects"] = {}
    return doc


def _k8s_inventory_asset_and_tag(item: dict, cluster_name: str) -> tuple[str | None, str | None]:
    kind = str(item.get("kind") or "").strip()
    name = str(item.get("name") or "").strip()
    namespace = str(item.get("namespace") or "").strip()
    if not (kind and name):
        return None, None
    cluster = (cluster_name or "cluster").strip() or "cluster"
    namespace_part = namespace or "cluster"
    # Scope config/RBAC posture to one asset per namespace (cluster-scoped objects
    # roll into the cluster asset) rather than a separate asset per object. Per-object
    # finding identity is preserved via the manifest filename (see the scan loop).
    asset = f"k8s/{cluster}/{namespace_part}"
    rbac_kinds = {"role", "rolebinding", "clusterrole", "clusterrolebinding"}
    tag = "rbac" if kind.lower() in rbac_kinds else "k8s-config"
    return asset, tag


def _safe_k8s_manifest_filename(item: dict) -> str:
    raw = _k8s_inventory_item_key(item).lower()
    return "".join(ch if ch.isalnum() else "-" for ch in raw).strip("-") or "object"


def _read_k8s_inventory_doc(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    if path.name.endswith(".gz.b64"):
        decoded = base64.b64decode(raw)
        return json.loads(gzip.decompress(decoded).decode("utf-8"))
    return json.loads(raw)


def _grype_scan(
    image: str,
    sbom_report: dict | None,
    docker_config_path: Path | None,
) -> dict | None:
    """Grype SCA second opinion. Reuses the CycloneDX SBOM when one was produced
    (grype scans the SBOM — no second registry pull); otherwise falls back to a
    direct image scan. grype's own vuln DB still differs from Trivy's."""
    if sbom_report:
        with tempfile.NamedTemporaryFile("w", suffix=".cdx.json") as f:
            json.dump(sbom_report, f)
            f.flush()
            return run_grype_sbom(Path(f.name), timeout=180)
    return run_grype_image_ref(image, timeout=240, docker_config_path=docker_config_path)


def _ingest_trivy_report_with_retry(
    *,
    vat_url: str,
    key: str,
    report: dict,
    asset_name: str,
    tag: str | None,
    image_digest: str | None,
) -> dict:
    import time

    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            return ingest_report(
                vat_url,
                key,
                report,
                asset=asset_name,
                tag=tag,
                image_digest=image_digest,
            )
        except VATClientError:
            if attempt == max_attempts:
                raise
            if _verbose_retry_logging_enabled():
                print(f"  trivy ingest attempt {attempt} failed; retrying...", file=sys.stderr)
            time.sleep(min(2**attempt, 16))
    raise VATClientError("Ingest failed")


def _ingest_json_report_with_retry(
    *,
    vat_url: str,
    key: str,
    report: dict,
    asset_name: str,
    tag: str | None,
    image_digest: str | None,
    label: str,
) -> dict:
    import time

    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            return ingest_report(
                vat_url,
                key,
                report,
                asset=asset_name,
                tag=tag,
                image_digest=image_digest,
            )
        except VATClientError:
            if attempt == max_attempts:
                raise
            if _verbose_retry_logging_enabled():
                print(f"  {label} ingest attempt {attempt} failed; retrying...", file=sys.stderr)
            time.sleep(min(2**attempt, 16))
    raise VATClientError("Ingest failed")


def _verbose_retry_logging_enabled() -> bool:
    return (os.environ.get("VAT_VERBOSE_RETRY_LOGS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@contextmanager
def _parser_key_cache_lock() -> Iterator[None]:
    """Serialize parser-key regeneration across aggregated worker processes."""
    lock_dir = key_cache_dir()
    lock_dir.mkdir(parents=True, exist_ok=True)
    with (lock_dir / "scanner-keys.lock").open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _ensure_parser_ingest_key(
    vat_url: str,
    admin_token: str,
    parser_id: str,
    *,
    reset_keys: bool = False,
    asset_type: str = "package",
) -> tuple[str, str | None]:
    with _parser_key_cache_lock():
        source_id, ensured_key = ensure_source(
            vat_url,
            admin_token,
            parser_id,
            create_key=True,
            regenerate_key=reset_keys,
            asset_type=asset_type,
        )
        # ensure_source mints a key only when the source has none yet; an existing
        # source returns key=None and we fall back to our persistent cache. We do
        # NOT auto-regenerate on a cache miss: rotating here invalidates the key
        # every other scanner already holds for this source. Persistent state
        # (node-agent hostPath, worker PVC) keeps the cache; a genuine reset needs
        # an explicit --reset-keys run.
        key = ensured_key or get_cached_key(source_id)
        if key:
            cache_key(source_id, key)
    if key:
        return source_id, key
    return source_id, None


def _load_runtime_containers(containerd_socket: Path) -> dict:
    endpoint = f"unix://{containerd_socket}"
    result = subprocess.run(
        ["crictl", "--runtime-endpoint", endpoint, "ps", "-a", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise VATClientError(result.stderr.strip() or "crictl ps failed")
    return json.loads(result.stdout or "{}")


def _load_runtime_images(containerd_socket: Path) -> dict:
    endpoint = f"unix://{containerd_socket}"
    result = subprocess.run(
        ["crictl", "--runtime-endpoint", endpoint, "images", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise VATClientError(result.stderr.strip() or "crictl images failed")
    return json.loads(result.stdout or "{}")


def _load_docker_containers(docker_socket: Path) -> list[dict]:
    if not docker_socket.exists():
        return []
    result = subprocess.run(
        [
            "docker",
            "--host",
            f"unix://{docker_socket}",
            "ps",
            "-a",
            "--format",
            "{{json .}}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise VATClientError(result.stderr.strip() or "docker ps failed")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def _load_docker_images(docker_socket: Path) -> list[dict]:
    if not docker_socket.exists():
        return []
    result = subprocess.run(
        [
            "docker",
            "--host",
            f"unix://{docker_socket}",
            "image",
            "ls",
            "--digests",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise VATClientError(result.stderr.strip() or "docker image ls failed")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def _runtime_image_signature(image: str, targets: list[dict], scan_types: list[str]) -> str:
    target_bits = [
        f"{target.get('asset','')}|{target.get('containerId','')}|{target.get('state','')}"
        for target in targets
    ]
    return f"{image}|targets={','.join(sorted(target_bits))}|scanTypes={','.join(scan_types)}"


def _runtime_trivy_image_src(targets: list[dict]) -> str:
    sources = {str(target.get("runtimeSource") or "").strip() for target in targets}
    ordered = [source for source in ("containerd", "docker") if source in sources]
    return ",".join(ordered) if ordered else "containerd,docker"


def _first_runtime_rootfs_path(targets: list[dict]) -> Path | None:
    for target in targets:
        raw = str(target.get("rootfsPath") or "").strip()
        if raw:
            path = Path(raw)
            if path.exists():
                return path
    return None


def _runtime_auth_inventory_item() -> dict:
    raw = os.environ.get("VAT_RUNTIME_IMAGE_PULL_SECRETS", "").strip()
    if not raw:
        return {}
    default_namespace = os.environ.get("POD_NAMESPACE", "vat-operator").strip() or "vat-operator"
    pull_secrets: list[dict[str, str]] = []
    for part in [piece.strip() for piece in raw.split(",") if piece.strip()]:
        if "/" in part:
            namespace, name = part.split("/", 1)
        else:
            namespace, name = default_namespace, part
        namespace = namespace.strip()
        name = name.strip()
        if namespace and name:
            pull_secrets.append({"namespace": namespace, "name": name})
    return {"targets": [{"pullSecrets": pull_secrets}]} if pull_secrets else {}


def cmd_scan_runtime(args: argparse.Namespace) -> int:
    """Scan images known to the local node container runtime, running or stopped."""
    vat_url = (args.vat_url or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (args.admin_token or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not vat_url or not (api_key or admin_token or args.dry_run):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    scan_types = _parse_runtime_scan_types(getattr(args, "scan_types", "") or None)
    parser_keys: dict[str, str] = {}
    if not args.dry_run and admin_token:
        for parser_id in ("trivy", "grype", "cyclonedx", "openscap"):
            if parser_id == "cyclonedx" and "image-sbom" not in scan_types:
                continue
            if parser_id == "trivy" and "image-sca" not in scan_types:
                continue
            if parser_id == "grype" and "image-grype" not in scan_types:
                continue
            if parser_id == "openscap" and "container-stig" not in scan_types:
                continue
            try:
                source_id, key = _ensure_parser_ingest_key(
                    vat_url,
                    admin_token,
                    parser_id,
                    reset_keys=bool(getattr(args, "reset_keys", False)),
                    asset_type="container" if parser_id == "openscap" else "package",
                )
            except VATClientError as e:
                print(f"\nERROR: {e}", file=sys.stderr)
                return 1
            if key:
                parser_keys[parser_id] = key
    elif api_key:
        parser_keys["trivy"] = api_key
        parser_keys["grype"] = api_key
        parser_keys["cyclonedx"] = api_key
        parser_keys["openscap"] = api_key

    cluster_name = (args.cluster_name or os.environ.get("VAT_CLUSTER_NAME", "cluster")).strip() or "cluster"
    node_name = (args.node_name or os.environ.get("NODE_NAME", "") or os.uname().nodename).strip() or "node"
    containerd_socket = Path(
        args.containerd_socket
        or os.environ.get("VAT_CONTAINERD_SOCKET_PATH", "/run/containerd/containerd.sock")
    )
    containerd_namespace = (
        args.containerd_namespace
        or os.environ.get("VAT_CONTAINERD_NAMESPACE", "k8s.io")
    ).strip() or "k8s.io"
    docker_socket = Path(
        getattr(args, "docker_socket", None)
        or os.environ.get("VAT_DOCKER_SOCKET_PATH", "/host/var/run/docker.sock")
    )

    state_path = Path(args.state_file) if getattr(args, "state_file", None) else None
    state = _load_scan_state(state_path)
    full_rescan = _full_rescan_due(
        state,
        int(getattr(args, "full_rescan_interval_seconds", 86400) or 86400),
        bool(getattr(args, "force_full_rescan", False)),
    )

    try:
        runtime_doc = _load_runtime_containers(containerd_socket)
    except (OSError, VATClientError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: unable to enumerate runtime containers: {e}", file=sys.stderr)
        return 1 if getattr(args, "fail_on_error", False) else 0

    targets = _runtime_targets_from_crictl(
        runtime_doc,
        cluster_name,
        node_name,
        containerd_socket=containerd_socket,
        containerd_namespace=containerd_namespace,
    )
    referenced_images = {str(target.get("image") or "").strip() for target in targets if target.get("image")}
    try:
        image_doc = _load_runtime_images(containerd_socket)
        targets.extend(
            _runtime_targets_from_crictl_images(
                image_doc,
                cluster_name,
                node_name,
                referenced_images=referenced_images,
            )
        )
    except (OSError, VATClientError, json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"WARN: unable to enumerate runtime images: {e}", file=sys.stderr)

    referenced_images = {str(target.get("image") or "").strip() for target in targets if target.get("image")}
    try:
        docker_container_targets = _runtime_targets_from_docker_containers(
            _load_docker_containers(docker_socket),
            cluster_name,
            node_name,
            docker_socket=docker_socket,
        )
        targets.extend(docker_container_targets)
    except (OSError, VATClientError, json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"WARN: unable to enumerate Docker containers: {e}", file=sys.stderr)

    referenced_images = {str(target.get("image") or "").strip() for target in targets if target.get("image")}
    try:
        targets.extend(
            _runtime_targets_from_docker_images(
                _load_docker_images(docker_socket),
                cluster_name,
                node_name,
                referenced_images=referenced_images,
            )
        )
    except (OSError, VATClientError, json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"WARN: unable to enumerate Docker images: {e}", file=sys.stderr)

    by_image: dict[str, list[dict]] = {}
    for target in targets:
        image = str(target.get("image") or "").strip()
        if image:
            by_image.setdefault(image, []).append(target)

    scanned = skipped = failures = scanner_failures = 0
    images_state = state.setdefault("images", {})
    auth_item = _runtime_auth_inventory_item()
    for image in sorted(by_image):
        image_targets = by_image[image]
        signature = _runtime_image_signature(image, image_targets, scan_types)
        item_state = images_state.get(image)
        if not full_rescan and isinstance(item_state, dict) and item_state.get("signature") == signature:
            skipped += 1
            continue

        print("Scanning runtime image:", image)
        local_rootfs = _first_runtime_rootfs_path(image_targets)
        image_src = _runtime_trivy_image_src(image_targets)
        with _temporary_registry_auth_config(auth_item) as docker_config_path:
            report = (
                run_trivy_image_ref(
                    image,
                    timeout=120,
                    docker_config_path=docker_config_path,
                    image_src=image_src,
                    containerd_address=str(containerd_socket),
                    containerd_namespace=containerd_namespace,
                )
                if "image-sca" in scan_types
                else None
            )
            sbom_report = (
                run_trivy_image_ref_cyclonedx(
                    image,
                    timeout=180,
                    docker_config_path=docker_config_path,
                    image_src=image_src,
                    containerd_address=str(containerd_socket),
                    containerd_namespace=containerd_namespace,
                )
                if "image-sbom" in scan_types
                else None
            )
            grype_report = (
                _grype_scan(image, sbom_report, docker_config_path)
                if "image-grype" in scan_types
                else None
            )
            stig_xml = None
            if "container-stig" in scan_types:
                if local_rootfs:
                    stig_xml = run_stig_rootfs(
                        local_rootfs,
                        image,
                        timeout=600,
                        verbose=False,
                    )
                if not stig_xml:
                    stig_xml = run_stig_image_ref(
                        image,
                        image,
                        timeout=600,
                        docker_config_path=docker_config_path,
                        verbose=False,
                    )
        if "image-sca" in scan_types and not report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Trivy runtime image scan failed or trivy not found.", file=sys.stderr)
            failures += 1
            scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1
        if "image-sbom" in scan_types and not sbom_report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Trivy CycloneDX runtime image scan failed or trivy not found.", file=sys.stderr)
            failures += 1
            scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1
        if "image-grype" in scan_types and not grype_report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Grype runtime image scan failed or grype not found.", file=sys.stderr)
            # Best-effort second opinion: don't add to `failures` (which gates
            # checkpoint/full-rescan seeding) so grype flakiness stays incremental.
            scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1
        if "container-stig" in scan_types and not stig_xml:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: OpenSCAP runtime STIG scan produced no results.", file=sys.stderr)
            failures += 1
            scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1

        target_failures = 0
        seen_target_assets: set[str] = set()
        for target in image_targets:
            asset = str(target.get("asset") or "").strip()
            if not asset:
                continue
            if asset in seen_target_assets:
                continue
            seen_target_assets.add(asset)
            tag = _image_ref_tag(image)
            target_image_digest = str(target.get("imageDigest") or "").strip() or None
            print("Asset:       ", asset)
            target_report = normalize_trivy(copy.deepcopy(report), asset) if report else None
            if target_report and getattr(args, "no_snippets", False):
                target_report = strip_snippets(target_report)
            target_grype_report = normalize_grype(copy.deepcopy(grype_report), asset) if grype_report else None
            target_sbom_report = copy.deepcopy(sbom_report) if sbom_report else None
            target_stig_xml = stig_xml
            if args.dry_run:
                if target_report:
                    print(f"  trivy: {len(target_report.get('Results') or [])} result(s)")
                if target_grype_report:
                    print(f"  grype: {len(target_grype_report.get('matches') or [])} result(s)")
                if target_sbom_report:
                    print(f"  cyclonedx: {len(target_sbom_report.get('components') or [])} component(s)")
                if target_stig_xml:
                    print(f"  openscap: {count_openscap_findings(target_stig_xml)} finding(s)")
                continue
            if target_report:
                try:
                    resp = _ingest_trivy_report_with_retry(
                        vat_url=vat_url,
                        key=parser_keys.get("trivy") or api_key,
                        report=target_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=target_image_digest,
                    )
                    print(f"  trivy: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
            if target_grype_report:
                grype_key = parser_keys.get("grype") or api_key
                if not grype_key:
                    target_failures += 1
                    print("\nERROR: No Grype ingest key available.", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue
                try:
                    resp = _ingest_json_report_with_retry(
                        vat_url=vat_url,
                        key=grype_key,
                        report=target_grype_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=target_image_digest,
                        label="grype",
                    )
                    print(f"  grype: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
            if target_stig_xml:
                openscap_key = parser_keys.get("openscap") or api_key
                if not openscap_key:
                    target_failures += 1
                    print("\nERROR: No OpenSCAP ingest key available.", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue
                try:
                    resp = ingest_openscap_report(
                        vat_url,
                        openscap_key,
                        target_stig_xml,
                        asset=asset,
                        tag=tag,
                        image_digest=target_image_digest,
                        idempotency_key=f"openscap:{asset}:{image}",
                    )
                    print(f"  openscap: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
            if target_sbom_report:
                cyclonedx_key = parser_keys.get("cyclonedx") or api_key
                if not cyclonedx_key:
                    target_failures += 1
                    print("\nERROR: No CycloneDX ingest key available.", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue
                try:
                    resp = _ingest_json_report_with_retry(
                        vat_url=vat_url,
                        key=cyclonedx_key,
                        report=target_sbom_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=target_image_digest,
                        label="cyclonedx",
                    )
                    print(f"  cyclonedx: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
        failures += target_failures
        if target_failures == 0:
            images_state[image] = {
                "signature": signature,
                "image": image,
                "scannedAt": datetime.now(timezone.utc).isoformat(),
            }
            scanned += 1
            _save_scan_state(state_path, state)

    if failures == 0 and (full_rescan or not state.get("lastFullScanAt")):
        state["lastFullScanAt"] = datetime.now(timezone.utc).isoformat()
        _save_scan_state(state_path, state)
    print(
        f"\nRuntime scan complete. images={len(by_image)} scanned={scanned} "
        f"skipped={skipped} targets={len(targets)} failures={failures} "
        f"scannerFailures={scanner_failures}"
    )
    return 1 if failures and getattr(args, "fail_on_error", False) else 0


def cmd_scan_inventory(args: argparse.Namespace) -> int:
    """Scan a deduplicated Kubernetes image inventory sequentially."""
    inventory_path = Path(args.inventory)
    try:
        doc = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: Unable to read inventory {inventory_path}: {e}", file=sys.stderr)
        return 1

    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        print("ERROR: Inventory must contain an items array.", file=sys.stderr)
        return 1

    vat_url = (getattr(args, "vat_url", "") or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (getattr(args, "admin_token", "") or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not args.dry_run and not (vat_url and (api_key or admin_token)):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    scan_types = _parse_inventory_scan_types(getattr(args, "scan_types", None))
    parser_keys: dict[str, str] = {}
    if not args.dry_run and admin_token:
        for parser_id in ("trivy", "grype", "cyclonedx"):
            if parser_id == "cyclonedx" and "image-sbom" not in scan_types:
                continue
            if parser_id == "trivy" and "image-sca" not in scan_types:
                continue
            if parser_id == "grype" and "image-grype" not in scan_types:
                continue
            try:
                source_id, key_to_cache = _ensure_parser_ingest_key(
                    vat_url,
                    admin_token,
                    parser_id,
                    reset_keys=args.reset_keys,
                    asset_type="container",
                )
            except VATClientError as e:
                print(f"\nERROR: {e}", file=sys.stderr)
                return 1
            if not key_to_cache:
                print(f"  {source_id}: no key", file=sys.stderr)
                return 1
            parser_keys[parser_id] = key_to_cache
    elif api_key:
        parser_keys["trivy"] = api_key
        parser_keys["grype"] = api_key
        parser_keys["cyclonedx"] = api_key

    key = parser_keys.get("trivy") or (api_key if not admin_token else "")
    if not args.dry_run and not key and "image-sca" in scan_types:
        try:
            source_id, key = _ensure_parser_ingest_key(
                vat_url,
                admin_token,
                "trivy",
                reset_keys=args.reset_keys,
                asset_type="container",
            )
        except VATClientError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
        if not key:
            print(f"  {source_id}: no key", file=sys.stderr)
            return 1
        parser_keys["trivy"] = key

    cluster_name = (
        getattr(args, "cluster_name", "")
        or os.environ.get("VAT_CLUSTER_NAME", "")
        or os.environ.get("CLUSTER_NAME", "")
        or "cluster"
    ).strip()
    state_file_value = (
        getattr(args, "state_file", None)
        or os.environ.get("VAT_SCAN_STATE_FILE", "")
        or ""
    )
    state_file = Path(state_file_value) if state_file_value else None
    state = _load_scan_state(state_file)
    full_rescan_due = _full_rescan_due(
        state,
        int(getattr(args, "full_rescan_interval_seconds", 0) or 0),
        bool(getattr(args, "force_full_rescan", False)),
    )

    failures = 0
    scanner_failures = 0
    scanned = 0
    skipped = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        image = str(item.get("image") or "").strip()
        if not image:
            continue
        item_key = _inventory_item_key(item)
        signature = _inventory_item_signature(item) + "|scanTypes=" + ",".join(scan_types)
        image_state = (state.get("images") or {}).get(item_key)
        if (
            not full_rescan_due
            and isinstance(image_state, dict)
            and image_state.get("signature") == signature
        ):
            skipped += 1
            print("Skipping unchanged image:", image)
            continue
        scanned += 1
        image_digest = str(item.get("imageDigest") or "").strip() or None
        targets = _inventory_targets(item)
        print("Scanning image:", image)
        with _temporary_registry_auth_config(item) as docker_config_path:
            report = (
                run_trivy_image_ref(image, timeout=120, docker_config_path=docker_config_path)
                if "image-sca" in scan_types
                else None
            )
            sbom_report = (
                run_trivy_image_ref_cyclonedx(image, timeout=180, docker_config_path=docker_config_path)
                if "image-sbom" in scan_types
                else None
            )
            grype_report = (
                _grype_scan(image, sbom_report, docker_config_path)
                if "image-grype" in scan_types
                else None
            )
        image_scanner_failures = 0
        if "image-sca" in scan_types and not report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Trivy image scan failed or trivy not found.", file=sys.stderr)
            scanner_failures += 1
            image_scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1
        if "image-grype" in scan_types and not grype_report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Grype image scan failed or grype not found.", file=sys.stderr)
            # Grype is a best-effort second opinion: surface the miss but do NOT
            # touch image_scanner_failures, so a flaky grype never blocks the
            # per-image checkpoint and forces perpetual rescans.
            scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1
        if "image-sbom" in scan_types and not sbom_report:
            if getattr(args, "fail_on_error", False) or getattr(args, "verbose", False):
                print("ERROR: Trivy CycloneDX image scan failed or trivy not found.", file=sys.stderr)
            scanner_failures += 1
            image_scanner_failures += 1
            if getattr(args, "fail_on_error", False):
                return 1

        if not targets:
            targets = [{"namespace": "unknown", "kind": "Image", "name": image, "containerName": "image"}]

        target_failures = image_scanner_failures
        seen_target_assets: set[str] = set()
        for target in targets:
            asset, tag = _inventory_target_asset_and_tag(target, cluster_name, image)
            if not asset:
                continue
            if asset in seen_target_assets:
                continue
            seen_target_assets.add(asset)
            print("Asset:       ", asset)
            if "image-sca" in scan_types and report:
                target_report = normalize_trivy(copy.deepcopy(report), asset)
                if getattr(args, "no_snippets", False):
                    target_report = strip_snippets(target_report)
            else:
                target_report = None
            target_grype_report = (
                normalize_grype(copy.deepcopy(grype_report), asset)
                if ("image-grype" in scan_types and grype_report)
                else None
            )
            target_sbom_report = copy.deepcopy(sbom_report) if sbom_report else None
            if args.dry_run:
                if target_report:
                    count = len(target_report.get("Results") or [])
                    print(f"  trivy: {count} result(s)")
                if target_grype_report:
                    count = len(target_grype_report.get("matches") or [])
                    print(f"  grype: {count} result(s)")
                if target_sbom_report:
                    count = len(target_sbom_report.get("components") or [])
                    print(f"  cyclonedx: {count} component(s)")
                continue
            if target_report:
                try:
                    resp = _ingest_trivy_report_with_retry(
                        vat_url=vat_url,
                        key=parser_keys.get("trivy") or key,
                        report=target_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=image_digest,
                    )
                    print(f"  trivy: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
            if target_grype_report:
                grype_key = parser_keys.get("grype")
                if not grype_key:
                    target_failures += 1
                    print("\nERROR: No Grype ingest key available.", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue
                try:
                    resp = _ingest_json_report_with_retry(
                        vat_url=vat_url,
                        key=grype_key,
                        report=target_grype_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=image_digest,
                        label="grype",
                    )
                    print(f"  grype: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
            if target_sbom_report:
                cyclonedx_key = parser_keys.get("cyclonedx") or api_key
                if not cyclonedx_key:
                    target_failures += 1
                    print("\nERROR: No CycloneDX ingest key available.", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue
                try:
                    resp = _ingest_json_report_with_retry(
                        vat_url=vat_url,
                        key=cyclonedx_key,
                        report=target_sbom_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=image_digest,
                        label="cyclonedx",
                    )
                    print(f"  cyclonedx: {resp}")
                except VATClientError as e:
                    target_failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
        failures += target_failures
        if target_failures == 0:
            images_state = state.setdefault("images", {})
            images_state[item_key] = {
                "signature": signature,
                "image": image,
                "imageDigest": image_digest,
                "lastScanAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            _save_scan_state(state_file, state)

    if failures == 0 and (full_rescan_due or not state.get("lastFullScanAt")):
        state["lastFullScanAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _save_scan_state(state_file, state)

    print(
        f"\nInventory scan complete. scanned={scanned} skipped={skipped} "
        f"failures={failures} scannerFailures={scanner_failures}"
    )
    return 0


def cmd_scan_k8s_inventory(args: argparse.Namespace) -> int:
    """Scan Kubernetes object/RBAC inventory for config and secret posture."""
    inventory_path = Path(args.inventory)
    try:
        doc = _read_k8s_inventory_doc(inventory_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: Unable to read Kubernetes inventory {inventory_path}: {e}", file=sys.stderr)
        return 1

    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        print("ERROR: Kubernetes inventory must contain an items array.", file=sys.stderr)
        return 1

    vat_url = (getattr(args, "vat_url", "") or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (getattr(args, "admin_token", "") or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not args.dry_run and not (vat_url and (api_key or admin_token)):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    key = ""
    if not args.dry_run and admin_token:
        try:
            source_id, key = _ensure_parser_ingest_key(
                vat_url,
                admin_token,
                "trivy",
                reset_keys=args.reset_keys,
                asset_type="repo",
            )
        except VATClientError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
        if not key:
            print(f"  {source_id}: no key", file=sys.stderr)
            return 1
    elif api_key:
        key = api_key
    if not args.dry_run and not key:
        print("\nERROR: No Trivy ingest key available.", file=sys.stderr)
        return 1

    # Gitleaks secret detection on the manifests (best-effort; catches inline env /
    # args secrets in workload specs). No key or binary => skip silently.
    gitleaks_key = ""
    if not args.dry_run and admin_token:
        try:
            _, gitleaks_key = _ensure_parser_ingest_key(
                vat_url,
                admin_token,
                "gitleaks",
                reset_keys=args.reset_keys,
                asset_type="repo",
            )
        except VATClientError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
    elif api_key:
        gitleaks_key = api_key

    cluster_name = (
        getattr(args, "cluster_name", None)
        or os.environ.get("VAT_CLUSTER_NAME", "")
        or "cluster"
    )
    state_path = getattr(args, "state_file", None) or os.environ.get("VAT_K8S_SCAN_STATE_FILE", "")
    state_file = Path(state_path) if state_path else None
    state = _load_k8s_scan_state(state_file)
    full_rescan = _full_rescan_due(
        state,
        int(getattr(args, "full_rescan_interval_seconds", 0) or 0),
        bool(getattr(args, "force_full_rescan", False)),
    )

    scanned = 0
    skipped = 0
    failures = 0
    with tempfile.TemporaryDirectory(prefix="vat-k8s-inventory-") as tmp:
        root = Path(tmp)
        for raw_item in items:
            if not isinstance(raw_item, dict):
                continue
            asset, tag = _k8s_inventory_asset_and_tag(raw_item, cluster_name)
            if not asset:
                continue
            item_key = _k8s_inventory_item_key(raw_item)
            signature = _k8s_inventory_item_signature(raw_item)
            previous = state.get("objects", {}).get(item_key, {})
            if not full_rescan and previous.get("signature") == signature:
                skipped += 1
                continue

            manifest = str(raw_item.get("manifest") or "").strip()
            if not manifest:
                skipped += 1
                continue
            safe_name = _safe_k8s_manifest_filename(raw_item)
            object_dir = root / safe_name
            object_dir.mkdir(parents=True, exist_ok=True)
            # Encode object identity in the filename so findings stay distinct once
            # every object in a namespace ingests under the same namespace asset.
            manifest_path = object_dir / f"{safe_name}.yaml"
            manifest_path.write_text(manifest + "\n", encoding="utf-8")
            print("Scanning object:", item_key)
            try:
                report = run_trivy_fs(
                    object_dir,
                    disable_artifact_scanning=True,
                    timeout=180,
                )
            except Exception as e:
                failures += 1
                print(f"ERROR: Trivy Kubernetes config scan failed for {item_key}: {e}", file=sys.stderr)
                if getattr(args, "fail_on_error", False):
                    return 1
                continue

            target_report = normalize_trivy(copy.deepcopy(report), asset)
            if getattr(args, "no_snippets", False):
                target_report = strip_snippets(target_report)
            if args.dry_run:
                count = len(target_report.get("Results") or [])
                print(f"  trivy: {count} result(s)")
            else:
                try:
                    resp = _ingest_json_report_with_retry(
                        vat_url=vat_url,
                        key=key,
                        report=target_report,
                        asset_name=asset,
                        tag=tag,
                        image_digest=None,
                        label="trivy",
                    )
                    print(f"  trivy: {resp}")
                except VATClientError as e:
                    failures += 1
                    print(f"\nERROR: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
                    continue

            gl_report = run_gitleaks(object_dir, timeout=120, temp_dir=root)
            if gl_report:
                gl_norm = normalize_gitleaks(gl_report, asset, tag)
                if args.dry_run:
                    findings = gl_norm.get("findings") if isinstance(gl_norm, dict) else gl_norm
                    print(f"  gitleaks: {len(findings or [])} finding(s)")
                elif gitleaks_key:
                    try:
                        resp = _ingest_json_report_with_retry(
                            vat_url=vat_url,
                            key=gitleaks_key,
                            report=gl_norm,
                            asset_name=asset,
                            tag=tag,
                            image_digest=None,
                            label="gitleaks",
                        )
                        print(f"  gitleaks: {resp}")
                    except VATClientError as e:
                        failures += 1
                        print(f"\nERROR: {e}", file=sys.stderr)
                        if getattr(args, "fail_on_error", False):
                            return 1
                        continue

            state.setdefault("objects", {})[item_key] = {
                "signature": signature,
                "scannedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            scanned += 1
            _save_scan_state(state_file, state)

    if failures == 0 and (full_rescan or not state.get("lastFullScanAt")):
        state["lastFullScanAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _save_scan_state(state_file, state)
    print(f"\nKubernetes inventory scan complete. scanned={scanned} skipped={skipped} failures={failures}")
    return 1 if failures and getattr(args, "fail_on_error", False) else 0


def cmd_scan_node(args: argparse.Namespace) -> int:
    """Run guarded node OpenSCAP lanes against a mounted host root."""
    host_root = Path(getattr(args, "host_root", None) or os.environ.get("VAT_HOST_ROOT", "/host"))
    node_name = (
        getattr(args, "node_name", None)
        or os.environ.get("NODE_NAME", "")
        or os.uname().nodename
    )
    cluster_name = (
        getattr(args, "cluster_name", None)
        or os.environ.get("VAT_CLUSTER_NAME", "")
        or "cluster"
    )
    scan_types = _parse_node_scan_types(getattr(args, "scan_types", None))
    asset = _node_asset(cluster_name, node_name)

    if not host_root.exists():
        print(f"Node scan skipped: host root {host_root} is not mounted.", file=sys.stderr)
        return 0
    if not (host_root / "etc" / "os-release").exists():
        print(f"Node scan skipped: {host_root}/etc/os-release is missing.", file=sys.stderr)
        return 0

    vat_url = (getattr(args, "vat_url", "") or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (getattr(args, "admin_token", "") or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run and not (vat_url and (api_key or admin_token)):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    parser_keys: dict[str, str] = {}
    if not dry_run and admin_token:
        for parser_id in ("openscap", "openscap_oval"):
            if parser_id == "openscap" and "node-stig" not in scan_types:
                continue
            if parser_id == "openscap_oval" and "node-oval-cve" not in scan_types:
                continue
            try:
                source_id, key = _ensure_parser_ingest_key(
                    vat_url,
                    admin_token,
                    parser_id,
                    reset_keys=args.reset_keys,
                    asset_type="container",
                )
            except VATClientError as e:
                print(f"\nERROR: {e}", file=sys.stderr)
                return 1
            if not key:
                print(f"  {source_id}: no key", file=sys.stderr)
                return 1
            parser_keys[parser_id] = key
    elif api_key:
        parser_keys["openscap"] = api_key
        parser_keys["openscap_oval"] = api_key

    timeout = int(getattr(args, "timeout", 600) or 600)
    verbose = bool(getattr(args, "verbose", False))
    failures = 0
    produced = 0
    skipped = 0

    print("Scanning node:", node_name)
    print("Asset:        ", asset)
    if "node-stig" in scan_types:
        try:
            xml = run_node_stig(host_root, asset, timeout=timeout, verbose=verbose)
        except Exception as e:
            failures += 1
            print(f"ERROR: node STIG scan failed: {e}", file=sys.stderr)
            if getattr(args, "fail_on_error", False):
                return 1
            xml = None
        if xml:
            produced += 1
            if dry_run:
                print(f"  openscap: {count_openscap_findings(xml)} finding(s)")
            else:
                key = parser_keys.get("openscap")
                if not key:
                    print("ERROR: No OpenSCAP ingest key available.", file=sys.stderr)
                    return 1
                try:
                    resp = ingest_openscap_report(
                        vat_url,
                        key,
                        xml,
                        asset=asset,
                        tag="node-stig",
                        idempotency_key=f"node-stig:{asset}",
                    )
                    print(f"  openscap: {resp}")
                except VATClientError as e:
                    failures += 1
                    print(f"ERROR: node STIG ingest failed: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
        else:
            skipped += 1
            print("  openscap: skipped (missing content or unsupported host)")

    if "node-oval-cve" in scan_types:
        try:
            xml = run_node_oval_cve(host_root, asset, timeout=timeout, verbose=verbose)
        except Exception as e:
            failures += 1
            print(f"ERROR: node OVAL CVE scan failed: {e}", file=sys.stderr)
            if getattr(args, "fail_on_error", False):
                return 1
            xml = None
        if xml:
            produced += 1
            if dry_run:
                print(f"  openscap_oval: {count_openscap_oval_findings(xml)} finding(s)")
            else:
                key = parser_keys.get("openscap_oval")
                if not key:
                    print("ERROR: No OpenSCAP OVAL ingest key available.", file=sys.stderr)
                    return 1
                try:
                    resp = ingest_openscap_oval_report(
                        vat_url,
                        key,
                        xml,
                        asset=asset,
                        tag="node-oval-cve",
                        idempotency_key=f"node-oval-cve:{asset}",
                    )
                    print(f"  openscap_oval: {resp}")
                except VATClientError as e:
                    failures += 1
                    print(f"ERROR: node OVAL CVE ingest failed: {e}", file=sys.stderr)
                    if getattr(args, "fail_on_error", False):
                        return 1
        else:
            skipped += 1
            print("  openscap_oval: skipped (missing content or unsupported host)")

    print(f"\nNode scan complete. reports={produced} skipped={skipped} failures={failures}")
    return 1 if failures and getattr(args, "fail_on_error", False) else 0


_QUEUE_SCAN_TYPES = ("image-sca", "image-sbom", "container-stig")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _scan_request_scan_types(spec: dict) -> list[str]:
    """ScanTypes from the CR spec, filtered to the supported set; default all three."""
    raw = spec.get("scanTypes") if isinstance(spec, dict) else None
    if isinstance(raw, list):
        chosen = [str(t).strip() for t in raw if str(t).strip() in _QUEUE_SCAN_TYPES]
        if chosen:
            return chosen
    return list(_QUEUE_SCAN_TYPES)


def _repo_without_tag(ref: str) -> str:
    r = ref.split("@", 1)[0]
    slash = r.rfind("/")
    colon = r.rfind(":")
    return r[:colon] if colon > slash else r


def _scan_request_pull_target(spec: dict) -> tuple[str, str, str | None, str | None]:
    """Resolve (pull_ref, asset, tag, image_digest) for a ScanRequest.

    Pull by digest (``repo@sha256:…``) for content-addressed scanning, but ingest
    under the tag ref so it maps to the same canonical container asset.
    """
    image_ref = str(spec.get("imageRef") or "").strip()
    digest = str(spec.get("digest") or "").strip() or None
    asset = image_ref.split("@", 1)[0]  # strip any digest from the asset/tag ref
    tag = _image_ref_tag(image_ref)
    if not tag:
        tags = spec.get("tags") if isinstance(spec, dict) else None
        if isinstance(tags, list) and tags:
            tag = str(tags[0]).strip() or None
    pull_ref = f"{_repo_without_tag(image_ref)}@{digest}" if digest else image_ref
    return pull_ref, asset, tag, digest


def _backoff_ready(status: dict, now: float, base: float = 30.0) -> bool:
    """Whether a previously-failed request is past its exponential backoff window."""
    attempts = int((status or {}).get("attempts") or 0)
    if attempts <= 0:
        return True
    finished = (status or {}).get("finishedAt")
    try:
        ts = datetime.fromisoformat(str(finished).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return True
    return now >= ts + base * (2 ** (attempts - 1))


def _scan_and_ingest_image(
    *,
    pull_ref: str,
    asset: str,
    tag: str | None,
    image_digest: str | None,
    scan_types: list[str],
    vat_url: str,
    parser_keys: dict[str, str],
    api_key: str,
    auth_item: dict,
    no_snippets: bool = False,
) -> bool:
    """Pull + scan one image ref and ingest. Returns True iff every requested
    scan produced a report and ingested cleanly."""
    with _temporary_registry_auth_config(auth_item) as docker_config_path:
        report = (
            run_trivy_image_ref(pull_ref, timeout=120, docker_config_path=docker_config_path)
            if "image-sca" in scan_types
            else None
        )
        sbom_report = (
            run_trivy_image_ref_cyclonedx(pull_ref, timeout=180, docker_config_path=docker_config_path)
            if "image-sbom" in scan_types
            else None
        )
        stig_xml = (
            run_stig_image_ref(pull_ref, asset, timeout=600, docker_config_path=docker_config_path)
            if "container-stig" in scan_types
            else None
        )

    ok = True
    if "image-sca" in scan_types:
        if not report:
            print("  ERROR: trivy image scan produced no report", file=sys.stderr)
            ok = False
        else:
            tr = normalize_trivy(report, asset)
            if no_snippets:
                tr = strip_snippets(tr)
            try:
                resp = _ingest_trivy_report_with_retry(
                    vat_url=vat_url, key=parser_keys.get("trivy") or api_key,
                    report=tr, asset_name=asset, tag=tag, image_digest=image_digest,
                )
                print(f"  trivy: {resp}")
            except VATClientError as e:
                print(f"  ERROR: trivy ingest: {e}", file=sys.stderr)
                ok = False

    if "image-sbom" in scan_types:
        if not sbom_report:
            print("  ERROR: trivy cyclonedx scan produced no report", file=sys.stderr)
            ok = False
        else:
            try:
                resp = _ingest_json_report_with_retry(
                    vat_url=vat_url, key=parser_keys.get("cyclonedx") or api_key,
                    report=sbom_report, asset_name=asset, tag=tag, image_digest=image_digest,
                    label="cyclonedx",
                )
                print(f"  cyclonedx: {resp}")
            except VATClientError as e:
                print(f"  ERROR: cyclonedx ingest: {e}", file=sys.stderr)
                ok = False

    if "container-stig" in scan_types:
        if not stig_xml:
            print("  ERROR: openscap STIG scan produced no report", file=sys.stderr)
            ok = False
        else:
            try:
                resp = ingest_openscap_report(
                    vat_url, parser_keys.get("openscap") or api_key, stig_xml,
                    asset=asset, tag=tag, image_digest=image_digest,
                    idempotency_key=f"openscap:{asset}:{image_digest or pull_ref}",
                )
                print(f"  openscap: {resp}")
            except VATClientError as e:
                print(f"  ERROR: openscap ingest: {e}", file=sys.stderr)
                ok = False
    return ok


def _resolve_queue_parser_keys(
    vat_url: str, admin_token: str, api_key: str, scan_types: set[str], reset_keys: bool
) -> dict[str, str]:
    """Mint/cache per-parser ingest keys (admin-token mode) or reuse the API key."""
    if admin_token:
        keys: dict[str, str] = {}
        wanted = [
            ("trivy", "image-sca", "package"),
            ("cyclonedx", "image-sbom", "package"),
            ("openscap", "container-stig", "container"),
        ]
        for parser_id, scan_type, asset_type in wanted:
            if scan_type not in scan_types:
                continue
            _, key = _ensure_parser_ingest_key(
                vat_url, admin_token, parser_id, reset_keys=reset_keys, asset_type=asset_type
            )
            if key:
                keys[parser_id] = key
        return keys
    return {"trivy": api_key, "cyclonedx": api_key, "openscap": api_key} if api_key else {}


def cmd_scan_queue(args: argparse.Namespace) -> int:
    """Drain pending ScanRequest CRs once: claim, pull-by-digest, scan, ingest, report."""
    import time

    from vat_scanner.scanrequests import K8sConflict, K8sError, ScanRequestClient

    vat_url = (getattr(args, "vat_url", "") or os.environ.get("VAT_URL", "")).strip()
    api_key = (getattr(args, "api_key", "") or os.environ.get("VAT_API_KEY", "")).strip()
    admin_token = (getattr(args, "admin_token", "") or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not vat_url or not (api_key or admin_token):
        print("\nERROR: Set VAT_URL and VAT_API_KEY or VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    client = ScanRequestClient()
    if not client.available():
        print("ERROR: scan-queue requires in-cluster service account token.", file=sys.stderr)
        return 1
    try:
        items = client.list()
    except K8sError as e:
        print(f"ERROR: listing ScanRequests: {e}", file=sys.stderr)
        return 1

    pod_namespace = os.environ.get("POD_NAMESPACE", "").strip() or client.namespace
    auth_item = {"targets": [{"namespace": pod_namespace}]}
    max_attempts = int(getattr(args, "max_attempts", 0) or os.environ.get("VAT_SCAN_QUEUE_MAX_ATTEMPTS", "") or 5)
    now = time.time()

    claimed = succeeded = failed = 0
    for obj in items:
        status = obj.get("status") or {}
        if str(status.get("phase") or "pending") not in ("", "pending"):
            continue
        if not _backoff_ready(status, now):
            continue

        prev_attempts = int(status.get("attempts") or 0)
        obj["status"] = {**status, "phase": "scanning", "startedAt": _now_iso(), "attempts": prev_attempts}
        try:
            obj = client.update_status(obj)
        except K8sConflict:
            continue  # another worker claimed it first
        except K8sError as e:
            print(f"  WARN: claim failed: {e}", file=sys.stderr)
            continue
        claimed += 1

        spec = obj.get("spec") or {}
        pull_ref, asset, tag, image_digest = _scan_request_pull_target(spec)
        scan_types = _scan_request_scan_types(spec)
        parser_keys = _resolve_queue_parser_keys(
            vat_url, admin_token, api_key, set(scan_types), bool(getattr(args, "reset_keys", False))
        )
        print(f"Scanning ScanRequest {obj['metadata']['name']}: pull={pull_ref} asset={asset} tag={tag}")

        ok = False
        try:
            ok = _scan_and_ingest_image(
                pull_ref=pull_ref, asset=asset, tag=tag, image_digest=image_digest,
                scan_types=scan_types, vat_url=vat_url, parser_keys=parser_keys,
                api_key=api_key, auth_item=auth_item, no_snippets=getattr(args, "no_snippets", False),
            )
        except Exception as e:  # noqa: BLE001 - never let one bad image kill the drain
            print(f"  ERROR: scan crashed: {e}", file=sys.stderr)

        result = obj.get("status") or {}
        if ok:
            succeeded += 1
            result.update({"phase": "done", "finishedAt": _now_iso(), "lastError": ""})
        else:
            failed += 1
            attempts = prev_attempts + 1
            result.update({
                "phase": "failed" if attempts >= max_attempts else "pending",
                "attempts": attempts,
                "finishedAt": _now_iso(),
                "lastError": "scan or ingest failed; see worker logs",
            })
        obj["status"] = result
        try:
            client.update_status(obj)
        except (K8sConflict, K8sError) as e:
            print(f"  WARN: status update failed: {e}", file=sys.stderr)

    print(f"\nscan-queue pass complete. claimed={claimed} done={succeeded} failed={failed}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Validate and show effective config."""
    path = Path(args.path).resolve() if args.path else Path.cwd()
    config_path = find_config_file(path, getattr(args, "config_path", None))

    if not config_path:
        print("No vat-scanner.yaml or .vat-scanner.yaml found.")
        print("Using defaults.")
        cfg = ScannerConfig(asset=path.name if path.is_dir() else ".")
    else:
        print(f"Config: {config_path}")
        cfg = ScannerConfig.from_file(config_path, path if path.is_dir() else None)

    if args.vat_url:
        cfg = cfg.merge_cli(vat_url=args.vat_url)
    if args.admin_token:
        cfg = cfg.merge_cli(admin_token="***")

    effective = {
        "vat_url": cfg.vat_url or "(not set)",
        "asset": cfg.asset or "(default from path)",
        "scan_types": cfg.scan_types,
        "exclude": cfg.exclude[:5],
        "scan_timeout_ms": cfg.scan_timeout_ms,
        "disable_artifact_scanning": cfg.disable_artifact_scanning,
        "temp_dir": cfg.temp_dir or "(default)",
    }
    print(json.dumps(effective, indent=2))
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    """Validate config file schema."""
    path = Path(args.path).resolve() if args.path else Path.cwd()
    config_path = find_config_file(path, getattr(args, "config_path", None))

    if not config_path:
        print("ERROR: No vat-scanner.yaml or .vat-scanner.yaml found.", file=sys.stderr)
        return 1

    try:
        raw = load_config_file(config_path)
    except Exception as e:
        print(f"ERROR: Invalid config: {e}", file=sys.stderr)
        return 1

    valid_keys = {"vat_url", "asset", "scan_types", "exclude", "gating", "scan_timeout_ms", "disable_artifact_scanning", "sarif_output", "temp_dir"}
    unknown = set(raw.keys()) - valid_keys
    if unknown:
        print(f"WARNING: Unknown keys: {unknown}", file=sys.stderr)

    if raw.get("scan_types"):
        st = raw["scan_types"]
        if not isinstance(st, list):
            print("ERROR: scan_types must be a list", file=sys.stderr)
            return 1
        invalid = set(st) - set(ALL_SCAN_TYPES)
        if invalid:
            print(f"ERROR: Invalid scan_types: {invalid}", file=sys.stderr)
            return 1

    print(f"Config valid: {config_path}")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    """Print version."""
    print(f"vat-scan {__version__}")
    return 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="vat-scan",
        description="VAT Local Scanner — scan locally, push only findings to VAT",
    )
    parser.add_argument("--config", dest="config_path", type=Path, help="Config file path")
    parser.add_argument("--vat-url", help="VAT instance URL (env: VAT_URL)")
    parser.add_argument("--api-key", help="Ingest API key (env: VAT_API_KEY)")
    parser.add_argument("--admin-token", help="Admin token for source creation (env: VAT_ADMIN_TOKEN)")
    parser.add_argument("--debug", action="store_true", help="Verbose output")
    parser.set_defaults(func=None)

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    sp_scan = subparsers.add_parser(
        "scan",
        help="Scan folder(s) and push to VAT. Pass multiple paths to scan several folders with one mount.",
    )
    sp_scan.add_argument(
        "paths",
        type=str,
        nargs="+",
        metavar="PATH",
        help="Folder(s) to scan (e.g. /scan/repo1 /scan/repo2 when /scan is mounted)",
    )
    sp_scan.add_argument("--asset", help="Asset name (default: path basename)")
    sp_scan.add_argument(
        "--asset-mode",
        choices=["single", "multi"],
        help="Asset targeting: multi (default) = one VAT asset per image/container target; "
        "single = one bundle asset (folder/--asset) with per-image labels as provenance",
    )
    sp_scan.add_argument(
        "--tag",
        help="Scan tag for package delineation (default: YYYY-MM-DD_HHMMSS for multiple scans per day)",
    )
    sp_scan.add_argument("--scan-types", help=f"Comma-separated: {','.join(ALL_SCAN_TYPES)}")
    sp_scan.add_argument(
        "--dev",
        action="store_true",
        help="Dev mode: limit container scans to 3 items for faster iteration",
    )
    sp_scan.add_argument("-v", "--verbose", action="store_true", help="Output scan progress")
    sp_scan.add_argument("--exclude", action="append", default=[], help="Exclude path (repeatable)")
    sp_scan.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_scan.add_argument("--gating-mode", choices=["release", "pr"], help="Gating mode")
    sp_scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail on severity")
    sp_scan.add_argument("--base-commit-id", help="For PR gating")
    sp_scan.add_argument("--head-commit-id", help="For PR gating")
    sp_scan.add_argument("--gating-result-output", type=str, help="JSON file for gating issues")
    sp_scan.add_argument("--scan-timeout", type=int, default=900_000, metavar="MS", help="Timeout in ms")
    sp_scan.add_argument("--disable-artifact-scanning", action="store_true", help="Skip Trivy rootfs")
    sp_scan.add_argument("--no-snippets", action="store_true", help="Omit code snippets from findings")
    sp_scan.add_argument("--sarif-output", type=str, metavar="FILE", help="Write findings to SARIF 2.1.0 file")
    sp_scan.add_argument("--reset-keys", action="store_true", help="Regenerate API keys")
    sp_scan.add_argument(
        "--temp-dir",
        type=str,
        metavar="DIR",
        help="Temp directory for scanner output (default: /tmp or VAT_SCANNER_TEMP_DIR)",
    )
    sp_scan.add_argument(
        "--save-openscap-xml",
        type=str,
        metavar="DIR",
        help="Save OpenSCAP XML reports to directory for debugging/validation",
    )
    sp_scan.set_defaults(func=cmd_scan)

    # scan-archive
    sp_arch = subparsers.add_parser(
        "scan-archive",
        help="Extract archive(s) to temp, scan, push to VAT, then delete extracted files.",
    )
    sp_arch.add_argument(
        "archives",
        type=str,
        nargs="+",
        metavar="ARCHIVE",
        help="Archive(s) to scan: .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz",
    )
    sp_arch.add_argument("--asset", help="Asset name (default: archive stem)")
    sp_arch.add_argument(
        "--asset-mode",
        choices=["single", "multi"],
        help="Asset targeting: multi (default) = per image/container; single = one bundle asset",
    )
    sp_arch.add_argument(
        "--tag",
        help="Scan tag for package delineation (default: YYYY-MM-DD_HHMMSS for multiple scans per day)",
    )
    sp_arch.add_argument("--scan-types", help=f"Comma-separated: {','.join(ALL_SCAN_TYPES)}")
    sp_arch.add_argument(
        "--dev",
        action="store_true",
        help="Dev mode: limit container scans to 3 items for faster iteration",
    )
    sp_arch.add_argument("-v", "--verbose", action="store_true", help="Output scan progress")
    sp_arch.add_argument("--exclude", action="append", default=[], help="Exclude path (repeatable)")
    sp_arch.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_arch.add_argument("--gating-mode", choices=["release", "pr"], help="Gating mode")
    sp_arch.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail on severity")
    sp_arch.add_argument("--base-commit-id", help="For PR gating")
    sp_arch.add_argument("--head-commit-id", help="For PR gating")
    sp_arch.add_argument("--gating-result-output", type=str, help="JSON file for gating issues")
    sp_arch.add_argument("--scan-timeout", type=int, default=900_000, metavar="MS", help="Timeout in ms")
    sp_arch.add_argument("--disable-artifact-scanning", action="store_true", help="Skip Trivy rootfs")
    sp_arch.add_argument("--no-snippets", action="store_true", help="Omit code snippets from findings")
    sp_arch.add_argument("--sarif-output", type=str, metavar="FILE", help="Write findings to SARIF 2.1.0 file")
    sp_arch.add_argument("--reset-keys", action="store_true", help="Regenerate API keys")
    sp_arch.add_argument(
        "--temp-dir",
        type=str,
        metavar="DIR",
        help="Temp directory for extraction and scanner output (default: /tmp)",
    )
    sp_arch.add_argument(
        "--save-openscap-xml",
        type=str,
        metavar="DIR",
        help="Save OpenSCAP XML reports to directory for debugging/validation",
    )
    sp_arch.set_defaults(func=cmd_scan_archive)

    # scan-image
    sp_img = subparsers.add_parser("scan-image", help="Scan container image")
    sp_img.add_argument("image", help="Image reference (e.g. myregistry/app:v1)")
    sp_img.add_argument("--asset", help="Asset name (default: derived from image)")
    sp_img.add_argument("--tag", help="Tag/branch context to attach to VAT ingest")
    sp_img.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_img.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_img.add_argument("--sarif-output", type=str, metavar="FILE", help="Write findings to SARIF 2.1.0 file")
    sp_img.add_argument("--image-digest", help="Image digest to attach to VAT ingest (env: VAT_SCAN_IMAGE_DIGEST)")
    sp_img.add_argument("--reset-keys", action="store_true", help="Regenerate API keys")
    sp_img.set_defaults(func=cmd_scan_image)

    # scan-inventory
    sp_inv = subparsers.add_parser("scan-inventory", help="Scan deduplicated Kubernetes image inventory")
    sp_inv.add_argument("inventory", type=Path, help="Inventory JSON file path")
    sp_inv.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_inv.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_inv.add_argument("--reset-keys", action="store_true", help="Regenerate API keys when admin-token mode is used")
    sp_inv.add_argument("--fail-on-error", action="store_true", help="Exit on first image scan failure")
    sp_inv.add_argument("--cluster-name", help="Kubernetes cluster name for asset IDs (env: VAT_CLUSTER_NAME)")
    sp_inv.add_argument("--state-file", type=Path, help="Persisted scan state file (env: VAT_SCAN_STATE_FILE)")
    sp_inv.add_argument(
        "--full-rescan-interval-seconds",
        type=int,
        default=86400,
        help="Rescan unchanged images after this many seconds; 0 disables scheduled full rescans",
    )
    sp_inv.add_argument("--force-full-rescan", action="store_true", help="Ignore scan state for this run")
    sp_inv.add_argument("--scan-types", default="", help="Comma-separated inventory scan types: image-sca,image-sbom")
    sp_inv.set_defaults(func=cmd_scan_inventory)

    # scan-runtime
    sp_runtime = subparsers.add_parser("scan-runtime", help="Scan local node runtime containers and images")
    sp_runtime.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_runtime.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_runtime.add_argument("--reset-keys", action="store_true", help="Regenerate API keys when admin-token mode is used")
    sp_runtime.add_argument("--fail-on-error", action="store_true", help="Exit on first runtime scan failure")
    sp_runtime.add_argument("--cluster-name", help="Kubernetes cluster name for asset IDs (env: VAT_CLUSTER_NAME)")
    sp_runtime.add_argument("--node-name", help="Kubernetes node name (env: NODE_NAME)")
    sp_runtime.add_argument(
        "--containerd-socket",
        type=Path,
        help="Containerd socket path (env: VAT_CONTAINERD_SOCKET_PATH)",
    )
    sp_runtime.add_argument(
        "--containerd-namespace",
        default="",
        help="Containerd namespace for Kubernetes images (env: VAT_CONTAINERD_NAMESPACE, default: k8s.io)",
    )
    sp_runtime.add_argument(
        "--docker-socket",
        type=Path,
        help="Host Docker socket path for Docker containers/images (env: VAT_DOCKER_SOCKET_PATH)",
    )
    sp_runtime.add_argument("--state-file", type=Path, help="Persisted runtime scan state file")
    sp_runtime.add_argument(
        "--full-rescan-interval-seconds",
        type=int,
        default=86400,
        help="Rescan unchanged runtime images after this many seconds; 0 disables scheduled full rescans",
    )
    sp_runtime.add_argument("--force-full-rescan", action="store_true", help="Ignore scan state for this run")
    sp_runtime.add_argument(
        "--scan-types",
        default="",
        help="Comma-separated runtime scan types: image-sca,image-sbom,container-stig",
    )
    sp_runtime.set_defaults(func=cmd_scan_runtime)

    # scan-k8s-inventory
    sp_k8s = subparsers.add_parser("scan-k8s-inventory", help="Scan Kubernetes object/RBAC inventory")
    sp_k8s.add_argument("inventory", type=Path, help="Kubernetes inventory JSON file path")
    sp_k8s.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_k8s.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_k8s.add_argument("--reset-keys", action="store_true", help="Regenerate API keys when admin-token mode is used")
    sp_k8s.add_argument("--fail-on-error", action="store_true", help="Exit on first object scan failure")
    sp_k8s.add_argument("--cluster-name", help="Kubernetes cluster name for asset IDs (env: VAT_CLUSTER_NAME)")
    sp_k8s.add_argument("--state-file", type=Path, help="Persisted scan state file (env: VAT_K8S_SCAN_STATE_FILE)")
    sp_k8s.add_argument(
        "--full-rescan-interval-seconds",
        type=int,
        default=86400,
        help="Rescan unchanged objects after this many seconds; 0 disables scheduled full rescans",
    )
    sp_k8s.add_argument("--force-full-rescan", action="store_true", help="Ignore scan state for this run")
    sp_k8s.set_defaults(func=cmd_scan_k8s_inventory)

    # scan-node
    sp_node = subparsers.add_parser("scan-node", help="Scan the mounted Kubernetes node host")
    sp_node.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_node.add_argument("--reset-keys", action="store_true", help="Regenerate API keys when admin-token mode is used")
    sp_node.add_argument("--fail-on-error", action="store_true", help="Exit on first node scan failure")
    sp_node.add_argument("--cluster-name", help="Kubernetes cluster name for asset IDs (env: VAT_CLUSTER_NAME)")
    sp_node.add_argument("--node-name", help="Kubernetes node name (env: NODE_NAME)")
    sp_node.add_argument("--host-root", type=Path, default=Path("/host"), help="Mounted host root path")
    sp_node.add_argument("--scan-types", default="", help="Comma-separated node scan types: node-stig,node-oval-cve")
    sp_node.add_argument("--timeout", type=int, default=600, help="OpenSCAP timeout in seconds")
    sp_node.add_argument("-v", "--verbose", action="store_true", help="Output scan progress")
    sp_node.set_defaults(func=cmd_scan_node)

    # scan-queue (event-driven consumer)
    sp_queue = subparsers.add_parser(
        "scan-queue", help="Drain pending ScanRequest CRs: claim, pull-by-digest, scan, ingest"
    )
    sp_queue.add_argument("--vat-url", default="", help="VAT base URL (env: VAT_URL)")
    sp_queue.add_argument("--api-key", default="", help="Ingest API key (env: VAT_API_KEY)")
    sp_queue.add_argument("--admin-token", default="", help="Admin token to mint keys (env: VAT_ADMIN_TOKEN)")
    sp_queue.add_argument("--reset-keys", action="store_true", help="Regenerate API keys (admin-token mode)")
    sp_queue.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_queue.add_argument(
        "--max-attempts", type=int, default=0,
        help="Fail after N attempts, then park for the backstop (env: VAT_SCAN_QUEUE_MAX_ATTEMPTS, default 5)",
    )
    sp_queue.set_defaults(func=cmd_scan_queue)

    # config
    sp_cfg = subparsers.add_parser("config", help="Validate and show effective config")
    sp_cfg.add_argument("path", type=str, default=".", nargs="?", help="Path to infer config from")
    sp_cfg.set_defaults(func=cmd_config)

    # config validate
    sp_val = subparsers.add_parser("config-validate", help="Validate config file schema")
    sp_val.add_argument("path", type=str, default=".", nargs="?", help="Path to infer config from")
    sp_val.set_defaults(func=cmd_config_validate)

    # version
    sp_ver = subparsers.add_parser("version", help="Print version")
    sp_ver.set_defaults(func=cmd_version)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
