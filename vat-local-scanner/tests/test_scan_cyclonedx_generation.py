"""Tests for CycloneDX report generation in scan orchestration."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vat_scanner.config import ScannerConfig
from vat_scanner.scan import run_scan


def test_run_scan_adds_cyclonedx_from_container_sources(monkeypatch, tmp_path: Path) -> None:
    """Dependencies scan should emit CycloneDX when container SBOM is available."""
    cfg = ScannerConfig(
        asset="bundle",
        scan_types=["dependencies", "stig"],
        tag="v-test",
        verbose=False,
    )

    container = SimpleNamespace(
        format="oci-layout",
        path=tmp_path / "img.layout",
        label="img-a",
        image_ref="ghcr.io/example/app:v1.2.3",
    )

    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr("vat_scanner.scan.collect_container_sources", lambda *args, **kwargs: ([container], []))
    monkeypatch.setattr("vat_scanner.scan.run_stig_oci_layout", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_stig_image", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        "vat_scanner.scan.run_trivy_oci_layout_cyclonedx",
        lambda *args, **kwargs: {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "openssl", "version": "3.0.0", "purl": "pkg:apk/openssl@3.0.0"}],
        },
    )
    monkeypatch.setattr("vat_scanner.scan.run_trivy_image_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs_cyclonedx", lambda *args, **kwargs: None)

    reports = run_scan(tmp_path, cfg)

    assert "cyclonedx" in reports
    docs = reports["cyclonedx"]
    assert isinstance(docs, list)
    assert len(docs) == 1
    doc, label, image_ref, image_digest = docs[0]
    assert label == "img-a"
    assert image_ref == "ghcr.io/example/app:v1.2.3"
    assert len(doc.get("components") or []) == 1
    props = doc["components"][0].get("properties") or []
    assert {"name": "vat:container_ref", "value": "ghcr.io/example/app:v1.2.3"} in props


def test_run_scan_cleans_wrap_dirs_after_cyclonedx(monkeypatch, tmp_path: Path) -> None:
    """Extracted OCI dirs must remain until CycloneDX generation finishes."""
    cfg = ScannerConfig(
        asset="bundle",
        scan_types=["dependencies", "stig"],
        tag="v-test",
        verbose=False,
    )

    extract_dir = tmp_path / "extract-wrap"
    extract_dir.mkdir()
    oci_layout = extract_dir / "img.layout"
    oci_layout.mkdir()

    container = SimpleNamespace(
        format="oci-layout",
        path=oci_layout,
        label="img-a",
        image_ref="ghcr.io/example/app:v1.2.3",
    )
    seen_exists: list[bool] = []
    events: list[str] = []

    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr(
        "vat_scanner.scan.collect_container_sources",
        lambda *args, **kwargs: ([container], [extract_dir]),
    )
    monkeypatch.setattr("vat_scanner.scan.run_stig_oci_layout", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_stig_image", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_image_cyclonedx", lambda *args, **kwargs: None)

    def _trivy_oci(*args, **kwargs):
        events.append("cyclonedx")
        seen_exists.append(oci_layout.exists())
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "openssl", "version": "3.0.0"}],
        }

    monkeypatch.setattr("vat_scanner.scan.run_trivy_oci_layout_cyclonedx", _trivy_oci)

    deleted: list[Path] = []
    monkeypatch.setattr(
        "vat_scanner.scan.shutil.rmtree",
        lambda p, ignore_errors=True: (events.append("cleanup"), deleted.append(Path(p))),
    )

    reports = run_scan(tmp_path, cfg)

    assert seen_exists == [True]
    assert extract_dir in deleted
    assert events.index("cyclonedx") < events.index("cleanup")
    assert "cyclonedx" in reports
    docs = reports["cyclonedx"]
    assert isinstance(docs, list)
    doc, label, image_ref, image_digest = docs[0]
    assert label == "img-a"
    assert image_ref == "ghcr.io/example/app:v1.2.3"
    props = doc["components"][0].get("properties") or []
    assert {"name": "vat:container_ref", "value": "ghcr.io/example/app:v1.2.3"} in props


def test_run_scan_dependencies_collects_container_sources(monkeypatch, tmp_path: Path) -> None:
    """Dependencies-only scan must still collect container sources for bundle SBOMs."""
    cfg = ScannerConfig(
        asset="bundle",
        scan_types=["dependencies"],
        tag="v-test",
        verbose=False,
    )

    container = SimpleNamespace(
        format="oci-layout",
        path=tmp_path / "img.layout",
        label="img-a",
        image_ref="ghcr.io/example/app:v1.2.3",
    )
    collect_calls = {"n": 0}

    def _collect(*args, **kwargs):
        collect_calls["n"] += 1
        return [container], []

    monkeypatch.setattr("vat_scanner.scan.collect_container_sources", _collect)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr("vat_scanner.scan.has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_fs_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr("vat_scanner.scan.run_trivy_image_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "vat_scanner.scan.run_trivy_oci_layout_cyclonedx",
        lambda *args, **kwargs: {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "openssl", "version": "3.0.0"}],
        },
    )

    reports = run_scan(tmp_path, cfg)
    assert collect_calls["n"] == 1
    assert "cyclonedx" in reports
