"""Scan orchestration: run scanners, normalize, return reports per parser."""

from __future__ import annotations

import re
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from vat_scanner.scanners.normalize import VAT_SCAN_TAG_KEY

from vat_scanner.config import ScannerConfig
from vat_scanner.scanners import (
    collect_container_sources,
    has_grype_content,
    has_npm_content,
    has_pip_content,
    has_semgrep_content,
    normalize_gitleaks,
    normalize_grype,
    normalize_trivy,
    run_gitleaks,
    run_grype,
    run_npm_audit,
    run_oval_cve_image,
    run_oval_cve_oci_layout,
    run_pip_audit,
    run_semgrep,
    run_stig_image,
    run_stig_oci_layout,
    run_trivy_fs_cyclonedx,
    run_trivy_fs,
    run_trivy_image_cyclonedx,
    run_trivy_image,
    run_trivy_oci_layout_cyclonedx,
    run_trivy_oci_layout,
)
from vat_scanner.snippet_enrichment import enrich_reports
from vat_scanner.scanners.runners import ScannerNotFoundError, ScannerTimeoutError


def _sanitize_asset_name(name: str) -> str:
    """Sanitize asset name for VAT."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "-", name.replace(" ", "-"))


def _verbose(config: ScannerConfig, msg: str) -> None:
    """Print message when verbose mode is on."""
    if config.verbose:
        print(f"  → {msg}", file=sys.stderr, flush=True)


def _fmt_elapsed(seconds: float) -> str:
    """Format elapsed seconds as human-readable string (e.g. 2.3s, 1m 23s)."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds // 60)
    s = seconds - m * 60
    return f"{m}m {s:.1f}s" if s >= 0.1 else f"{m}m"


def _apply_cyclonedx_container_ref(doc: dict | None, container_ref: str | None) -> dict | None:
    """Stamp VAT container reference into CycloneDX component properties."""
    if not isinstance(doc, dict):
        return None
    ref = (container_ref or "").strip()
    if not ref:
        return doc
    components = doc.get("components") or []
    if not isinstance(components, list):
        return doc
    out = dict(doc)
    patched_components: list[dict] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        props = c.get("properties") or []
        if not isinstance(props, list):
            props = []
        has_ref = False
        for p in props:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip().lower()
            if name in {"vat:container_ref", "vat.container_ref"}:
                has_ref = True
                break
        if not has_ref:
            props = [*props, {"name": "vat:container_ref", "value": ref}]
        patched_components.append({**c, "properties": props})
    out["components"] = patched_components
    return out


def _publish_report(
    on_report: Callable[[str, dict | list], None] | None,
    parser: str,
    report: dict | list,
) -> None:
    if on_report is not None:
        on_report(parser, report)


def run_scan(
    path: Path,
    config: ScannerConfig,
    *,
    on_report: Callable[[str, dict | list], None] | None = None,
) -> dict[str, dict | list]:
    """
    Run scanners based on config.scan_types and content detection.
    Returns dict of parser_id -> report (normalized for VAT ingest).
    """
    path = path.resolve()
    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    asset_name = config.asset or path.name
    asset_name = _sanitize_asset_name(asset_name)
    asset_mode = (getattr(config, "asset_mode", "single") or "single").strip().lower()
    rewrite_target = asset_mode != "multi"
    scan_tag = config.tag or ""

    scan_types = set(config.scan_types)
    timeout_sec = max(60, config.scan_timeout_ms // 1000)

    reports: dict[str, dict | list] = {}
    scan_totals: dict[str, float] = {}
    overall_start = time.perf_counter()
    container_timings: dict[str, list[float]] = {
        "trivy_container_item": [],
        "stig_item": [],
        "oval_cve_item": [],
        "cyclonedx_item": [],
    }
    trivy_cyclonedx_modes: dict[str, int] = {}

    # Trivy fs: secrets, iac, license, (optionally vuln/dependencies via artifact)
    run_trivy = (
        "secrets" in scan_types
        or "iac" in scan_types
        or "license" in scan_types
        or "dependencies" in scan_types
    )
    temp_dir = Path(config.temp_dir) if config.temp_dir else None

    if run_trivy:
        try:
            _verbose(config, "Trivy filesystem scan (secrets/iac/license)")
            t0 = time.perf_counter()
            trivy_fs = run_trivy_fs(
                path,
                disable_artifact_scanning=config.disable_artifact_scanning,
                timeout=timeout_sec,
                exclude=config.exclude,
                temp_dir=temp_dir,
            )
            enrich_reports({"trivy": trivy_fs}, path)
            trivy_fs = normalize_trivy(trivy_fs, asset_name, scan_tag, rewrite_target=rewrite_target)
            reports["trivy"] = trivy_fs
            _publish_report(on_report, "trivy", reports["trivy"])
            scan_totals["trivy_fs"] = time.perf_counter() - t0
            _verbose(config, f"Trivy fs completed in {_fmt_elapsed(scan_totals['trivy_fs'])}")
        except (ScannerNotFoundError, ScannerTimeoutError) as e:
            raise RuntimeError(str(e)) from e

    # Container images: docker-save tars + OCI layouts from .wrap bundles
    container_sources: list = []
    extract_dirs: list = []
    if (
        "container" in scan_types
        or "stig" in scan_types
        or "oval_cve" in scan_types
        or "dependencies" in scan_types
    ):
        _verbose(config, "Collecting container sources (docker-save, OCI layouts)")
        t0 = time.perf_counter()
        container_sources, extract_dirs = collect_container_sources(
            path, temp_dir=temp_dir, exclude=config.exclude
        )
        scan_totals["container_discovery"] = time.perf_counter() - t0
        if config.dev_limit > 0 and len(container_sources) > config.dev_limit:
            _verbose(config, f"Dev mode: limiting to {config.dev_limit} container(s)")
            container_sources = container_sources[: config.dev_limit]

    if "container" in scan_types and container_sources:
        n_container = len(container_sources)
        _verbose(config, f"Scanning {n_container} container image(s) with Trivy")
        trivy_timeout = min(120, timeout_sec)
        if "trivy" in reports:
            trivy_results = reports["trivy"].get("Results") or []
        else:
            trivy_results = []
        trivy_container_start = time.perf_counter()

        def _scan_container(src: object) -> tuple[dict | None, float]:
            t0 = time.perf_counter()
            if src.format == "docker-save":
                img_report = run_trivy_image(src.path, timeout=trivy_timeout)
            else:
                img_report = run_trivy_oci_layout(src.path, timeout=trivy_timeout)
            return img_report, time.perf_counter() - t0

        max_workers = min(2, n_container)
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                container_results = list(executor.map(_scan_container, container_sources))
        else:
            container_results = [_scan_container(src) for src in container_sources]

        for i, (src, result_pair) in enumerate(zip(container_sources, container_results), 1):
            img_report, elapsed = result_pair
            container_timings["trivy_container_item"].append(elapsed)
            if n_container > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → Trivy {i}/{n_container}: {src.label}{time_suffix}", flush=True)
            if img_report:
                # Use bundle asset so findings appear as sub-assets under kamiwaza-bundle
                # Pass source_image so parser can set file_path for provenance (which container had the vuln)
                img_report = normalize_trivy(
                    img_report,
                    asset_name,
                    scan_tag,
                    source_image=src.label,
                    image_ref=src.image_ref,
                    rewrite_target=rewrite_target,
                    canonical_image_digest=getattr(src, "image_digest", None),
                )
                trivy_results.extend(img_report.get("Results") or [])
        scan_totals["trivy_container"] = time.perf_counter() - trivy_container_start
        if config.verbose:
            print(f"  Trivy container: {n_container} scan(s) in {_fmt_elapsed(scan_totals['trivy_container'])}", flush=True)
        if trivy_results:
            reports["trivy"] = reports.get("trivy") or {}
            reports["trivy"]["Results"] = trivy_results
            _publish_report(on_report, "trivy", reports["trivy"])

    # STIG: Chainguard OpenSCAP GPOS SRG for container images
    if container_sources and config.verbose and "stig" not in scan_types:
        _verbose(config, "STIG (OpenSCAP) skipped (add 'stig' to --scan-types to enable)")
    if "stig" in scan_types and container_sources:
        n_stig = len(container_sources)
        _verbose(config, f"STIG (OpenSCAP) on {n_stig} container(s)")
        stig_reports: list[str] = []
        stig_timeout = min(600, timeout_sec)  # 10 min per image; large images can take several minutes
        stig_verbose = config.verbose
        stig_start = time.perf_counter()
        for i, src in enumerate(container_sources, 1):
            t0 = time.perf_counter()
            if src.format == "docker-save":
                xml = run_stig_image(
                    src.path,
                    f"{asset_name}:{src.label}",
                    timeout=stig_timeout,
                    temp_dir=temp_dir,
                    verbose=stig_verbose,
                )
            else:
                xml = run_stig_oci_layout(
                    src.path,
                    f"{asset_name}:{src.label}",
                    timeout=stig_timeout,
                    temp_dir=temp_dir,
                    verbose=stig_verbose,
                )
            # Only show detailed errors for first failure to avoid spam
            if stig_verbose and xml is None:
                stig_verbose = False
            elapsed = time.perf_counter() - t0
            container_timings["stig_item"].append(elapsed)
            if n_stig > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → STIG {i}/{n_stig}: {src.label}{time_suffix}", flush=True)
            if xml:
                stig_reports.append(
                    (xml, src.label, src.image_ref, getattr(src, "image_digest", None))
                )
        scan_totals["stig"] = time.perf_counter() - stig_start
        if config.verbose:
            print(f"  STIG total: {n_stig} scan(s) in {_fmt_elapsed(scan_totals['stig'])}", flush=True)
        if stig_reports:
            reports["openscap"] = stig_reports
            _publish_report(on_report, "openscap", reports["openscap"])
        elif container_sources:
            print(
                "  WARN: STIG (OpenSCAP) produced no results. Ensure Docker socket is mounted "
                "(e.g. -v /var/run/docker.sock:/var/run/docker.sock) and Chainguard openscap image is pullable.",
                file=sys.stderr,
                flush=True,
            )

    # OVAL CVE: OpenSCAP oscap-docker image-cve (configurable, opt-in)
    if container_sources and config.verbose and "oval_cve" not in scan_types:
        _verbose(config, "OVAL CVE (OpenSCAP) skipped (add 'oval_cve' to --scan-types to enable)")
    if "oval_cve" in scan_types and container_sources:
        n_oval = len(container_sources)
        _verbose(config, f"OVAL CVE (OpenSCAP) on {n_oval} container(s)")
        oval_timeout = min(600, timeout_sec)
        oval_verbose = config.verbose
        oval_reports: list[str] = []
        oval_start = time.perf_counter()
        oval_skipped_non_rhel = False
        for i, src in enumerate(container_sources, 1):
            t0 = time.perf_counter()
            if src.format == "docker-save":
                xml, skip_remaining = run_oval_cve_image(
                    src.path,
                    f"{asset_name}:{src.label}",
                    timeout=oval_timeout,
                    temp_dir=temp_dir,
                    verbose=oval_verbose,
                )
            else:
                xml, skip_remaining = run_oval_cve_oci_layout(
                    src.path,
                    f"{asset_name}:{src.label}",
                    timeout=oval_timeout,
                    temp_dir=temp_dir,
                    verbose=oval_verbose,
                )
            if skip_remaining:
                oval_skipped_non_rhel = True
                elapsed = time.perf_counter() - t0
                container_timings["oval_cve_item"].append(elapsed)
                if n_oval > 1 or config.verbose:
                    time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                    print(f"  → OVAL CVE {i}/{n_oval}: {src.label}{time_suffix}", flush=True)
                print(
                    "  OVAL CVE (OpenSCAP) skipped: images are not RHEL-based. "
                    "oscap-docker image-cve only supports RHEL/Fedora CVE streams.",
                    file=sys.stderr,
                    flush=True,
                )
                break
            if oval_verbose and xml is None:
                oval_verbose = False
            elapsed = time.perf_counter() - t0
            container_timings["oval_cve_item"].append(elapsed)
            if n_oval > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → OVAL CVE {i}/{n_oval}: {src.label}{time_suffix}", flush=True)
            if xml:
                oval_reports.append(
                    (xml, src.label, src.image_ref, getattr(src, "image_digest", None))
                )
        scan_totals["oval_cve"] = time.perf_counter() - oval_start
        if config.verbose and not oval_skipped_non_rhel:
            print(f"  OVAL CVE total: {n_oval} scan(s) in {_fmt_elapsed(scan_totals['oval_cve'])}", flush=True)
        if oval_reports:
            reports["openscap_oval"] = oval_reports
            _publish_report(on_report, "openscap_oval", reports["openscap_oval"])
        elif container_sources and not oval_skipped_non_rhel:
            print(
                "  WARN: OVAL CVE (OpenSCAP) produced no results. Ensure Docker socket is mounted "
                "and oscap-docker image-cve is supported (RHEL/Fedora-based images).",
                file=sys.stderr,
                flush=True,
            )

    # Dependencies: Grype, npm audit, pip-audit
    if "dependencies" in scan_types:
        # Always generate CycloneDX from Trivy so SBOM export includes packages
        # even when there are no vulnerability findings.
        cyclonedx_docs: list[tuple[dict, str, str | None, str | None]] = []
        t0 = time.perf_counter()
        fs_cdx = run_trivy_fs_cyclonedx(
            path,
            timeout=min(180, timeout_sec),
            exclude=config.exclude,
            temp_dir=temp_dir,
        )
        if fs_cdx:
            doc = _apply_cyclonedx_container_ref(fs_cdx, asset_name)
            if doc:
                cyclonedx_docs.append((doc, asset_name, None, None))
        if container_sources:
            trivy_cdx_timeout = min(180, timeout_sec)

            def _scan_cyclonedx(src: object) -> tuple[dict | None, float, dict[str, int]]:
                t0 = time.perf_counter()
                local_modes: dict[str, int] = {}
                if src.format == "docker-save":
                    img_cdx = run_trivy_image_cyclonedx(
                        src.path,
                        timeout=trivy_cdx_timeout,
                        mode_stats=local_modes,
                    )
                else:
                    img_cdx = run_trivy_oci_layout_cyclonedx(
                        src.path,
                        timeout=trivy_cdx_timeout,
                        mode_stats=local_modes,
                    )
                return img_cdx, time.perf_counter() - t0, local_modes

            max_workers = min(2, len(container_sources))
            if max_workers > 1:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    cdx_results = list(executor.map(_scan_cyclonedx, container_sources))
            else:
                cdx_results = [_scan_cyclonedx(src) for src in container_sources]

            for src, result_pair in zip(container_sources, cdx_results):
                img_cdx, elapsed, local_modes = result_pair
                for key, val in local_modes.items():
                    trivy_cyclonedx_modes[key] = trivy_cyclonedx_modes.get(key, 0) + val
                container_timings["cyclonedx_item"].append(elapsed)
                if img_cdx:
                    container_ref = src.image_ref or src.label
                    doc = _apply_cyclonedx_container_ref(img_cdx, container_ref)
                    if doc:
                        cyclonedx_docs.append(
                            (
                                doc,
                                src.label,
                                src.image_ref,
                                getattr(src, "image_digest", None),
                            )
                        )
        total_cyclonedx_components = sum(
            len((d.get("components") or []))
            for d, _, _, _ in cyclonedx_docs
            if isinstance(d, dict)
        )
        if cyclonedx_docs:
            reports["cyclonedx"] = cyclonedx_docs
            _publish_report(on_report, "cyclonedx", reports["cyclonedx"])
        if config.verbose:
            doc_count = len(cyclonedx_docs)
            print(
                f"  → CycloneDX docs: {doc_count}, components: {total_cyclonedx_components}",
                flush=True,
            )
        scan_totals["trivy_cyclonedx"] = time.perf_counter() - t0
        if total_cyclonedx_components == 0:
            raise RuntimeError(
                "Dependencies scan requested but CycloneDX SBOM has zero components. "
                "Failing scan to avoid stale SBOM exports."
            )

        if has_grype_content(path):
            _verbose(config, "Grype (dependencies)")
            t0 = time.perf_counter()
            grype_report = run_grype(path, timeout=min(120, timeout_sec), exclude=config.exclude)
            scan_totals["grype"] = time.perf_counter() - t0
            _verbose(config, f"Grype completed in {_fmt_elapsed(scan_totals['grype'])}")
            if grype_report:
                grype_report = normalize_grype(grype_report, asset_name, scan_tag)
                reports["grype"] = grype_report
                _publish_report(on_report, "grype", reports["grype"])

        if has_npm_content(path):
            _verbose(config, "npm audit")
            t0 = time.perf_counter()
            npm_report = run_npm_audit(path, timeout=min(60, timeout_sec))
            if npm_report:
                if isinstance(npm_report, dict) and scan_tag:
                    npm_report = dict(npm_report)
                    npm_report[VAT_SCAN_TAG_KEY] = scan_tag
                reports["npm_audit"] = npm_report
                _publish_report(on_report, "npm_audit", reports["npm_audit"])
            scan_totals["npm_audit"] = time.perf_counter() - t0
            _verbose(config, f"npm audit completed in {_fmt_elapsed(scan_totals['npm_audit'])}")

        if has_pip_content(path):
            _verbose(config, "pip-audit")
            t0 = time.perf_counter()
            pip_report = run_pip_audit(path, timeout=min(60, timeout_sec))
            if pip_report:
                if isinstance(pip_report, dict):
                    pip_report = dict(pip_report)
                    if scan_tag:
                        pip_report[VAT_SCAN_TAG_KEY] = scan_tag
                elif isinstance(pip_report, list) and scan_tag:
                    pip_report = {VAT_SCAN_TAG_KEY: scan_tag, "dependencies": pip_report}
                reports["pip_audit"] = pip_report
                _publish_report(on_report, "pip_audit", reports["pip_audit"])
            scan_totals["pip_audit"] = time.perf_counter() - t0
            _verbose(config, f"pip-audit completed in {_fmt_elapsed(scan_totals['pip_audit'])}")

    # Code: Semgrep
    if "code" in scan_types and has_semgrep_content(path):
        _verbose(config, "Semgrep (SAST)")
        t0 = time.perf_counter()
        semgrep_report = run_semgrep(path, timeout=min(180, timeout_sec), exclude=config.exclude)
        if semgrep_report:
            results = semgrep_report.get("results") or []
            if results:
                if isinstance(semgrep_report, dict) and scan_tag:
                    semgrep_report = dict(semgrep_report)
                    semgrep_report[VAT_SCAN_TAG_KEY] = scan_tag
                reports["semgrep"] = semgrep_report
                _publish_report(on_report, "semgrep", reports["semgrep"])
        scan_totals["semgrep"] = time.perf_counter() - t0
        _verbose(config, f"Semgrep completed in {_fmt_elapsed(scan_totals['semgrep'])}")

    # Secrets: Gitleaks (in addition to Trivy)
    if "secrets" in scan_types:
        _verbose(config, "Gitleaks (secrets)")
        t0 = time.perf_counter()
        gitleaks_report = run_gitleaks(path, timeout=min(120, timeout_sec), temp_dir=temp_dir)
        if gitleaks_report:
            if isinstance(gitleaks_report, list):
                findings = gitleaks_report
            else:
                findings = gitleaks_report.get("findings") or gitleaks_report.get("Findings") or []
            if findings:
                reports["gitleaks"] = normalize_gitleaks(gitleaks_report, asset_name, scan_tag)
                _publish_report(on_report, "gitleaks", reports["gitleaks"])
        scan_totals["gitleaks"] = time.perf_counter() - t0
        _verbose(config, f"Gitleaks completed in {_fmt_elapsed(scan_totals['gitleaks'])}")

    # Clean up extracted wrap bundles after all scans that may read OCI layouts.
    for d in extract_dirs:
        shutil.rmtree(d, ignore_errors=True)

    # Overall total (verbose only)
    overall_elapsed = time.perf_counter() - overall_start
    if config.verbose and scan_totals:
        parts = [f"{k}: {_fmt_elapsed(v)}" for k, v in sorted(scan_totals.items())]
        if parts:
            print(f"  Scan totals: {', '.join(parts)}", flush=True)
        if trivy_cyclonedx_modes:
            mode_parts = [f"{k}={v}" for k, v in sorted(trivy_cyclonedx_modes.items())]
            print(f"  Trivy CycloneDX mode totals: {', '.join(mode_parts)}", flush=True)
        for metric, values in container_timings.items():
            if values:
                avg = sum(values) / len(values)
                print(
                    f"  {metric}: n={len(values)}, avg={_fmt_elapsed(avg)}, max={_fmt_elapsed(max(values))}",
                    flush=True,
                )
        print(f"  Total scan time: {_fmt_elapsed(overall_elapsed)}", flush=True)

    return reports
