"""VAT Local Scanner CLI — vat-scan."""

from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from pathlib import Path

from vat_scanner import __version__
from vat_scanner.config import (
    ALL_SCAN_TYPES,
    ScannerConfig,
    find_config_file,
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
    source_id_for_parser,
)
from vat_scanner.sarif_output import reports_to_sarif
from vat_scanner.scanners import run_trivy_image_ref
from vat_scanner.scanners.normalize import normalize_trivy
from vat_scanner.archive import extract_archive, is_archive, remove_extracted
from vat_scanner.container_identity import canonical_container_asset
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
        cfg = ScannerConfig(asset=first_path.name)
    cfg = _merge_scan_cli(cfg, args)

    def _prepare_report_for_push(parser: str, report: object, scan_root: Path, no_snippets: bool) -> object:
        payload = copy.deepcopy(report)
        if no_snippets:
            payload = strip_snippets(payload)
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
        cfg = ScannerConfig(asset=archive_paths[0].stem)
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
    admin_token = (args.admin_token or os.environ.get("VAT_ADMIN_TOKEN", "")).strip()
    if not vat_url or not admin_token:
        print("\nERROR: Set VAT_URL and VAT_ADMIN_TOKEN.", file=sys.stderr)
        return 1

    try:
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
        resp = ingest_report(vat_url, key, report, asset=asset_name, tag=tag_val)
        print(f"  trivy: {resp}")
    except VATClientError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1

    print("\nDone. Asset:", asset_name)
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
    sp_img.add_argument("--dry-run", action="store_true", help="Scan only; do not push")
    sp_img.add_argument("--no-snippets", action="store_true", help="Omit code snippets")
    sp_img.add_argument("--sarif-output", type=str, metavar="FILE", help="Write findings to SARIF 2.1.0 file")
    sp_img.add_argument("--reset-keys", action="store_true", help="Regenerate API keys")
    sp_img.set_defaults(func=cmd_scan_image)

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
