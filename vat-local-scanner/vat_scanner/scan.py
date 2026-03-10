"""Scan orchestration: run scanners, normalize, return reports per parser."""

from __future__ import annotations

import re
import shutil
import sys
import time
from pathlib import Path

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
    run_trivy_fs,
    run_trivy_image,
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


def run_scan(path: Path, config: ScannerConfig) -> dict[str, dict | list]:
    """
    Run scanners based on config.scan_types and content detection.
    Returns dict of parser_id -> report (normalized for VAT ingest).
    """
    path = path.resolve()
    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    asset_name = config.asset or path.name
    asset_name = _sanitize_asset_name(asset_name)
    scan_tag = config.tag or ""

    scan_types = set(config.scan_types)
    timeout_sec = max(60, config.scan_timeout_ms // 1000)

    reports: dict[str, dict | list] = {}
    scan_totals: dict[str, float] = {}
    overall_start = time.perf_counter()

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
            trivy_fs = normalize_trivy(trivy_fs, asset_name, scan_tag)
            reports["trivy"] = trivy_fs
            scan_totals["trivy_fs"] = time.perf_counter() - t0
            _verbose(config, f"Trivy fs completed in {_fmt_elapsed(scan_totals['trivy_fs'])}")
        except (ScannerNotFoundError, ScannerTimeoutError) as e:
            raise RuntimeError(str(e)) from e

    # Container images: docker-save tars + OCI layouts from .wrap bundles
    container_sources: list = []
    extract_dirs: list = []
    if "container" in scan_types or "stig" in scan_types or "oval_cve" in scan_types:
        _verbose(config, "Collecting container sources (docker-save, OCI layouts)")
        container_sources, extract_dirs = collect_container_sources(
            path, temp_dir=temp_dir
        )
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
        for i, src in enumerate(container_sources, 1):
            t0 = time.perf_counter()
            if src.format == "docker-save":
                img_report = run_trivy_image(src.path, timeout=trivy_timeout)
            else:
                img_report = run_trivy_oci_layout(src.path, timeout=trivy_timeout)
            elapsed = time.perf_counter() - t0
            if n_container > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → Trivy {i}/{n_container}: {src.label}{time_suffix}", flush=True)
            if img_report:
                # Use bundle asset so findings appear as sub-assets under kamiwaza-bundle
                # Pass source_image so parser can set file_path for provenance (which container had the vuln)
                img_report = normalize_trivy(
                    img_report, asset_name, scan_tag, source_image=src.label
                )
                trivy_results.extend(img_report.get("Results") or [])
        scan_totals["trivy_container"] = time.perf_counter() - trivy_container_start
        if config.verbose:
            print(f"  Trivy container: {n_container} scan(s) in {_fmt_elapsed(scan_totals['trivy_container'])}", flush=True)
        if trivy_results:
            reports["trivy"] = reports.get("trivy") or {}
            reports["trivy"]["Results"] = trivy_results

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
            if n_stig > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → STIG {i}/{n_stig}: {src.label}{time_suffix}", flush=True)
            if xml:
                stig_reports.append((xml, src.label))
        scan_totals["stig"] = time.perf_counter() - stig_start
        if config.verbose:
            print(f"  STIG total: {n_stig} scan(s) in {_fmt_elapsed(scan_totals['stig'])}", flush=True)
        if stig_reports:
            reports["openscap"] = stig_reports
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
            if n_oval > 1 or config.verbose:
                time_suffix = f" ({_fmt_elapsed(elapsed)})" if config.verbose else ""
                print(f"  → OVAL CVE {i}/{n_oval}: {src.label}{time_suffix}", flush=True)
            if xml:
                oval_reports.append((xml, src.label))
        scan_totals["oval_cve"] = time.perf_counter() - oval_start
        if config.verbose and not oval_skipped_non_rhel:
            print(f"  OVAL CVE total: {n_oval} scan(s) in {_fmt_elapsed(scan_totals['oval_cve'])}", flush=True)
        if oval_reports:
            reports["openscap_oval"] = oval_reports
        elif container_sources and not oval_skipped_non_rhel:
            print(
                "  WARN: OVAL CVE (OpenSCAP) produced no results. Ensure Docker socket is mounted "
                "and oscap-docker image-cve is supported (RHEL/Fedora-based images).",
                file=sys.stderr,
                flush=True,
            )

    # Clean up extracted wrap bundles
    for d in extract_dirs:
        shutil.rmtree(d, ignore_errors=True)

    # Dependencies: Grype, npm audit, pip-audit
    if "dependencies" in scan_types:
        if has_grype_content(path):
            _verbose(config, "Grype (dependencies)")
            t0 = time.perf_counter()
            grype_report = run_grype(path, timeout=min(120, timeout_sec), exclude=config.exclude)
            scan_totals["grype"] = time.perf_counter() - t0
            _verbose(config, f"Grype completed in {_fmt_elapsed(scan_totals['grype'])}")
            if grype_report:
                grype_report = normalize_grype(grype_report, asset_name, scan_tag)
                reports["grype"] = grype_report

        if has_npm_content(path):
            _verbose(config, "npm audit")
            t0 = time.perf_counter()
            npm_report = run_npm_audit(path, timeout=min(60, timeout_sec))
            if npm_report:
                if isinstance(npm_report, dict) and scan_tag:
                    npm_report = dict(npm_report)
                    npm_report[VAT_SCAN_TAG_KEY] = scan_tag
                reports["npm_audit"] = npm_report
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
        scan_totals["gitleaks"] = time.perf_counter() - t0
        _verbose(config, f"Gitleaks completed in {_fmt_elapsed(scan_totals['gitleaks'])}")

    # Overall total (verbose only)
    overall_elapsed = time.perf_counter() - overall_start
    if config.verbose and scan_totals:
        parts = [f"{k}: {_fmt_elapsed(v)}" for k, v in sorted(scan_totals.items())]
        if parts:
            print(f"  Scan totals: {', '.join(parts)}", flush=True)
        print(f"  Total scan time: {_fmt_elapsed(overall_elapsed)}", flush=True)

    return reports
