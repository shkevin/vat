"""Regression tests for scanner optimization behavior."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from vat_scanner.config import ScannerConfig
from vat_scanner.scan import run_scan
from vat_scanner.scanners.detection import collect_container_sources
from vat_scanner.vat_client import _ingest_headers


def test_run_scan_calls_on_report_for_incremental_publish(monkeypatch, tmp_path: Path) -> None:
    cfg = ScannerConfig(asset="bundle", scan_types=["dependencies"], tag="scan-1", verbose=False)
    container = SimpleNamespace(
        format="docker-save",
        path=tmp_path / "img.tar",
        label="img-a",
        image_ref="ghcr.io/example/app:v1",
    )

    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr("vat_scanner.scan.collect_container_sources", lambda *args, **kwargs: ([container], []))
    monkeypatch.setattr(
        "vat_scanner.scan.run_trivy_fs_cyclonedx",
        lambda *args, **kwargs: {"bomFormat": "CycloneDX", "components": [{"name": "openssl"}]},
    )
    monkeypatch.setattr("vat_scanner.scan.run_trivy_image_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr("vat_scanner.scan.has_npm_content", lambda *args, **kwargs: False)
    monkeypatch.setattr("vat_scanner.scan.has_pip_content", lambda *args, **kwargs: False)

    seen: list[str] = []
    reports = run_scan(tmp_path, cfg, on_report=lambda parser, report: seen.append(parser))
    assert "trivy" in reports
    assert "cyclonedx" in reports
    assert "trivy" in seen
    assert "cyclonedx" in seen


def test_collect_container_sources_reads_tar_listing_once(monkeypatch, tmp_path: Path) -> None:
    tar_path = tmp_path / "bundle.tar"
    tar_path.write_text("stub")
    calls: list[list[str]] = []

    class _Result:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    def _fake_run(cmd, capture_output=True, text=True, timeout=30, check=False):
        calls.append(cmd)
        if cmd[:2] == ["tar", "-tf"]:
            return _Result(0, "manifest.json\n")
        if cmd[:2] == ["tar", "-xOf"]:
            return _Result(0, json.dumps([{"RepoTags": ["ghcr.io/test/app:v1"]}]))
        return _Result(1, "")

    monkeypatch.setattr("vat_scanner.scanners.detection.subprocess.run", _fake_run)

    sources, _extract = collect_container_sources(tmp_path)
    tar_listing_calls = [c for c in calls if c[:2] == ["tar", "-tf"]]
    assert len(tar_listing_calls) == 1
    assert len(sources) == 1
    assert sources[0].format == "docker-save"


def test_ingest_headers_include_scan_session_fields() -> None:
    headers = _ingest_headers(
        "k",
        asset="asset",
        tag="tag",
        source_image="img",
        scan_id="scan-123",
        scan_status="running",
        idempotency_key="idem-1",
    )
    assert headers["X-VAT-Scan-Id"] == "scan-123"
    assert headers["X-VAT-Scan-Status"] == "running"
    assert headers["X-VAT-Idempotency-Key"] == "idem-1"
