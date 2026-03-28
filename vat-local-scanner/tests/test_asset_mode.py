"""Tests for scanner asset-mode behavior."""

from pathlib import Path

from vat_scanner.cli import _ingest_headers_for_item
from vat_scanner.config import ScannerConfig
from vat_scanner.scan import run_scan


def _base_monkeypatch(monkeypatch):
    monkeypatch.setattr(
        "vat_scanner.scan.run_trivy_fs",
        lambda *args, **kwargs: {"Results": [{"Target": "original-target", "Vulnerabilities": []}]},
    )
    monkeypatch.setattr("vat_scanner.scan.collect_container_sources", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr("vat_scanner.scan.run_semgrep", lambda *args, **kwargs: {})
    monkeypatch.setattr("vat_scanner.scan.run_gitleaks", lambda *args, **kwargs: {})
    monkeypatch.setattr("vat_scanner.scan.run_grype", lambda *args, **kwargs: {})
    monkeypatch.setattr("vat_scanner.scan.has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        "vat_scanner.scan.run_trivy_fs_cyclonedx",
        lambda *args, **kwargs: {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "openssl", "version": "3.0.0"}],
        },
    )
    monkeypatch.setattr("vat_scanner.scan.run_trivy_image_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_oci_layout_cyclonedx", lambda *args, **kwargs: None)


def test_single_asset_mode_rewrites_trivy_target(monkeypatch, tmp_path: Path) -> None:
    _base_monkeypatch(monkeypatch)
    cfg = ScannerConfig(asset="bundle-asset", asset_mode="single", scan_types=["dependencies"])
    reports = run_scan(tmp_path, cfg)
    target = reports["trivy"]["Results"][0]["Target"]
    assert target == "bundle-asset"


def test_multi_asset_mode_preserves_trivy_target(monkeypatch, tmp_path: Path) -> None:
    _base_monkeypatch(monkeypatch)
    cfg = ScannerConfig(asset="bundle-asset", asset_mode="multi", scan_types=["dependencies"])
    reports = run_scan(tmp_path, cfg)
    target = reports["trivy"]["Results"][0]["Target"]
    assert target == "original-target"


def test_default_asset_mode_is_multi() -> None:
    cfg = ScannerConfig()
    assert cfg.asset_mode == "multi"


def test_ingest_headers_bundle_keeps_source_image() -> None:
    assert _ingest_headers_for_item("kamiwaza-bundle", "redis") == (
        "kamiwaza-bundle",
        "redis",
        None,
    )


def test_ingest_headers_multi_uses_aikido_style_asset_and_tag() -> None:
    assert _ingest_headers_for_item(None, "metrics-server", None) == (
        "containers/images/metrics-server",
        None,
        "latest",
    )
    assert _ingest_headers_for_item(None, "oci-tar-label", None) == (
        "containers/images/oci-tar-label",
        None,
        "latest",
    )
