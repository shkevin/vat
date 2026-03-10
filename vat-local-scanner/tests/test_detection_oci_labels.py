"""
Unit tests for OCI layout label resolution.
Run without real artifacts: pytest vat-local-scanner/tests/test_detection_oci_labels.py -v
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vat_scanner.scanners.detection import (
    _get_chart_images_lock,
    _get_imgpkg_images_lock,
    _get_oci_image_ref_name,
    _process_wrap_sources,
    _sanitize_image_ref_for_label,
)


def _make_oci_layout(root: Path, layout_name: str, ref_name: str | None = None) -> Path:
    """Create minimal OCI layout dir with oci-layout + index.json."""
    layout_dir = root / layout_name
    layout_dir.mkdir(parents=True)
    (layout_dir / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    manifests = [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:abc"}]
    if ref_name:
        manifests[0]["annotations"] = {"org.opencontainers.image.ref.name": ref_name}
    (layout_dir / "index.json").write_text(json.dumps({"manifests": manifests}))
    return layout_dir


@pytest.fixture
def wrap_extract(tmp_path: Path) -> Path:
    """Synthetic extracted wrap root (tests create kamiwaza-0.2.0/images/ as needed)."""
    return tmp_path


def test_sanitize_image_ref_for_label() -> None:
    assert _sanitize_image_ref_for_label("redis:7") == "redis-7"
    assert _sanitize_image_ref_for_label("ghcr.io/foo/bar:v1") == "bar-v1"
    assert _sanitize_image_ref_for_label("library/redis:7") == "redis-7"


def test_get_oci_image_ref_name_has_ref(tmp_path: Path) -> None:
    layout = _make_oci_layout(tmp_path, "redis.layout", "redis:7")
    assert _get_oci_image_ref_name(layout) == "redis:7"


def test_get_oci_image_ref_name_no_ref(tmp_path: Path) -> None:
    layout = _make_oci_layout(tmp_path, "abc123.layout", ref_name=None)
    assert _get_oci_image_ref_name(layout) is None


def test_imgpkg_images_lock_parses_kbld_id(tmp_path: Path) -> None:
    """ImagesLock with kbld.carvel.dev/id should map digest -> ref."""
    imgpkg = tmp_path / ".imgpkg"
    imgpkg.mkdir()
    images_yml = imgpkg / "images.yml"
    images_yml.write_text("""
images:
- image: ghcr.io/some/redis@sha256:a4ef811c93f6deadbeef1234567890abcdef1234567890abcdef1234567890ab
  annotations:
    kbld.carvel.dev/id: redis:7
""")
    digest_to_ref = _get_imgpkg_images_lock(tmp_path)
    # Full digest normalized to hex only
    full_hex = "a4ef811c93f6deadbeef1234567890abcdef1234567890abcdef1234567890ab"
    assert full_hex in digest_to_ref or any(full_hex[:12] in d for d in digest_to_ref)
    # Should have redis:7 for matching digest
    vals = list(digest_to_ref.values())
    assert "redis:7" in vals


def test_process_wrap_sources_from_index_ref(wrap_extract: Path) -> None:
    """When index.json has org.opencontainers.image.ref.name, use it for label."""
    images_dir = wrap_extract / "kamiwaza-0.2.0" / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    layout = _make_oci_layout(images_dir, "a4ef811c93f6.layout", "redis:7")
    sources = _process_wrap_sources(wrap_extract, "kamiwaza", "uid123")
    assert len(sources) == 1
    assert sources[0].label == "kamiwaza-images-redis-7"


def test_process_wrap_sources_from_imgpkg(wrap_extract: Path) -> None:
    """When .imgpkg/images.yml has digest->ref, use it when index has no ref."""
    base = wrap_extract / "kamiwaza-0.2.0"
    base.mkdir(parents=True, exist_ok=True)
    images_dir = base / "images"
    images_dir.mkdir()
    # Layout dir name = short digest (12 chars) - matches ImagesLock
    layout = _make_oci_layout(images_dir, "a4ef811c93f6.layout", ref_name=None)
    imgpkg = base / ".imgpkg"
    imgpkg.mkdir()
    (imgpkg / "images.yml").write_text("""
images:
- image: ghcr.io/foo/redis@sha256:a4ef811c93f6deadbeef1234567890abcdef1234567890abcdef1234567890ab
  annotations:
    kbld.carvel.dev/id: redis:7
""")
    sources = _process_wrap_sources(wrap_extract, "kamiwaza", "uid123")
    assert len(sources) == 1
    # Should resolve via digest match
    assert "redis" in sources[0].label
    assert sources[0].label != "kamiwaza-images-a4ef811c93f6"


def test_process_wrap_sources_fallback_to_digest(wrap_extract: Path) -> None:
    """When no ref in index and no ImagesLock, fall back to digest short."""
    base = wrap_extract / "kamiwaza-0.2.0"
    base.mkdir(parents=True, exist_ok=True)
    images_dir = base / "images"
    images_dir.mkdir()
    layout = _make_oci_layout(images_dir, "a4ef811c93f6.layout", ref_name=None)
    # No .imgpkg/images.yml
    sources = _process_wrap_sources(wrap_extract, "kamiwaza", "uid123")
    assert len(sources) == 1
    assert sources[0].label == "kamiwaza-images-a4ef811c93f6"


def test_chart_images_lock_parses_kajiya_format(tmp_path: Path) -> None:
    """chart/Images.lock (kajiya) should map digest -> image ref."""
    chart = tmp_path / "foo-0.1.0" / "chart"
    chart.mkdir(parents=True)
    lock = chart / "Images.lock"
    lock.write_text("""
apiVersion: v0
kind: ImagesLock
images:
  - name: redis-1
    image: ghcr.io/foo/redis:7
    digests:
      - digest: sha256:455f5f147345c92d1900b4e8f9335dc72fec86bce2f0842a59982f523a9ebf54
        arch: linux/amd64
""")
    digest_to_ref = _get_chart_images_lock(tmp_path)
    full_hex = "455f5f147345c92d1900b4e8f9335dc72fec86bce2f0842a59982f523a9ebf54"
    assert full_hex in digest_to_ref
    assert digest_to_ref[full_hex] == "ghcr.io/foo/redis:7"


def test_process_wrap_sources_from_chart_images_lock(wrap_extract: Path) -> None:
    """When chart/Images.lock (kajiya) has digest->ref, use it for label."""
    base = wrap_extract / "kamiwaza-0.2.0"
    base.mkdir(parents=True, exist_ok=True)
    (base / "chart").mkdir(exist_ok=True)
    (base / "chart" / "Images.lock").write_text("""
apiVersion: v0
kind: ImagesLock
images:
  - name: redis-1
    image: ghcr.io/foo/redis:7
    digests:
      - digest: sha256:455f5f147345c92d1900b4e8f9335dc72fec86bce2f0842a59982f523a9ebf54
        arch: linux/amd64
""")
    images_dir = base / "images"
    images_dir.mkdir(exist_ok=True)
    # Layout dir name = full 64-char digest (kajiya format)
    layout = _make_oci_layout(
        images_dir,
        "455f5f147345c92d1900b4e8f9335dc72fec86bce2f0842a59982f523a9ebf54.layout",
        ref_name=None,
    )
    sources = _process_wrap_sources(wrap_extract, "kamiwaza", "uid123")
    assert len(sources) == 1
    assert sources[0].label == "kamiwaza-images-redis-7"


def test_process_wrap_sources_imgpkg_digest_mismatch(wrap_extract: Path) -> None:
    """
    When layout dir name does NOT match any digest in ImagesLock, fall back to digest.
    This simulates kajiya format where layout dir may use a different naming scheme.
    """
    base = wrap_extract / "kamiwaza-0.2.0"
    base.mkdir(parents=True, exist_ok=True)
    images_dir = base / "images"
    images_dir.mkdir()
    # Layout dir: "xyz999.layout" - not in ImagesLock
    layout = _make_oci_layout(images_dir, "xyz999.layout", ref_name=None)
    imgpkg = base / ".imgpkg"
    imgpkg.mkdir()
    (imgpkg / "images.yml").write_text("""
images:
- image: ghcr.io/foo/redis@sha256:a4ef811c93f6deadbeef1234567890abcdef1234567890abcdef1234567890ab
  annotations:
    kbld.carvel.dev/id: redis:7
""")
    sources = _process_wrap_sources(wrap_extract, "kamiwaza", "uid123")
    assert len(sources) == 1
    # No match -> fall back to layout dir name
    assert sources[0].label == "kamiwaza-images-xyz999"
