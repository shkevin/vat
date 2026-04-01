from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vat_scanner.scanners import detection, normalize


def test_normalize_gitleaks_handles_list_and_dict() -> None:
    out_list = normalize.normalize_gitleaks([{"x": 1}], "asset-a", scan_tag="scan-1")
    assert out_list["target"] == "asset-a"
    assert out_list[normalize.VAT_SCAN_TAG_KEY] == "scan-1"

    out_dict = normalize.normalize_gitleaks({"findings": []}, "asset-b")
    assert out_dict["target"] == "asset-b"
    assert normalize.normalize_gitleaks("noop", "asset-c") == "noop"


def test_normalize_trivy_sets_source_and_container_identity(monkeypatch) -> None:
    monkeypatch.setattr(
        normalize,
        "canonical_container_asset",
        lambda image_ref, source_image: ("containers/images/my-app", "latest"),
    )
    monkeypatch.setattr(normalize, "image_digest_from_ref", lambda image_ref: "sha256:abc")
    report = {
        "Results": [
            {"Target": "/tmp/work/.env"},
            {"target": "old-target"},
        ]
    }
    out = normalize.normalize_trivy(
        report,
        "bundle-asset",
        scan_tag="scan-7",
        source_image="ghcr.io/acme/my-app:latest",
        image_ref="ghcr.io/acme/my-app@sha256:abc",
    )
    for row in out["Results"]:
        assert row["Target"] == "bundle-asset"
        assert row["target"] == "bundle-asset"
        assert row[normalize.VAT_SOURCE_IMAGE_KEY] == "ghcr.io/acme/my-app:latest"
        assert row[normalize.VAT_CONTAINER_IMAGE_KEY] == "containers/images/my-app"
        assert row[normalize.VAT_CONTAINER_TAG_KEY] == "latest"
        assert row[normalize.VAT_CONTAINER_DIGEST_KEY] == "sha256:abc"
    assert out[normalize.VAT_SCAN_TAG_KEY] == "scan-7"


def test_normalize_trivy_digest_from_report_repo_digests_when_ref_has_no_sha() -> None:
    """Trivy often omits @sha256 in ref but still emits RepoDigests (OCI / loaded tags)."""
    report = {
        "Metadata": {
            "RepoDigests": [
                "ghcr.io/acme/my-app@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            ]
        },
        "Results": [{"Target": "img"}],
    }
    out = normalize.normalize_trivy(
        report,
        "bundle-asset",
        source_image="kamiwaza-images-core",
        image_ref="ghcr.io/acme/my-app:latest",
    )
    want = (
        "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )
    assert out["Results"][0][normalize.VAT_CONTAINER_DIGEST_KEY] == want


def test_normalize_trivy_digest_from_artifact_id_when_oci_input_has_no_repo_digests() -> None:
    """``trivy image --input <oci>`` often has RepoDigests null but ArtifactID set."""
    report = {
        "ArtifactID": "sha256:83b2b6703a620bf2e001ab57f7adc414d891787b3c59859b1b62909e48dd2242",
        "Metadata": {
            "OS": {"Family": "alpine"},
            "ImageID": "sha256:83b2b6703a620bf2e001ab57f7adc414d891787b3c59859b1b62909e48dd2242",
        },
        "Results": [{"Target": "img"}],
    }
    out = normalize.normalize_trivy(
        report,
        "bundle-asset",
        source_image="metrics-server-images-metrics-server-release-0.11.0",
        image_ref=None,
    )
    assert (
        out["Results"][0][normalize.VAT_CONTAINER_DIGEST_KEY]
        == "sha256:83b2b6703a620bf2e001ab57f7adc414d891787b3c59859b1b62909e48dd2242"
    )


def test_normalize_trivy_preserves_original_target_when_requested() -> None:
    report = {"Results": [{"Target": "app/secret.txt"}, "invalid-row"]}
    out = normalize.normalize_trivy(report, "bundle", rewrite_target=False)
    assert out["Results"][0]["Target"] == "app/secret.txt"
    assert out["Results"][0][normalize.VAT_SOURCE_PATH_KEY] == "app/secret.txt"


def test_normalize_grype_rewrites_source() -> None:
    report = {"source": {"target": "old", "userInput": "old"}}
    out = normalize.normalize_grype(report, "asset-name", scan_tag="scan-2")
    assert out["source"]["target"] == "asset-name"
    assert out["source"]["userInput"] == "asset-name"
    assert out[normalize.VAT_SCAN_TAG_KEY] == "scan-2"


def test_detection_has_any_and_content_helpers(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "requirements.txt"
    deep.parent.mkdir(parents=True)
    deep.write_text("flask", encoding="utf-8")
    assert not detection._has_any(tmp_path, ("requirements.txt",), max_depth=4)

    npm = tmp_path / "package.json"
    npm.write_text("{}", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert detection.has_npm_content(tmp_path)
    assert detection.has_pip_content(tmp_path)
    assert detection.has_grype_content(tmp_path)

    code = tmp_path / "src" / "main.py"
    code.parent.mkdir(exist_ok=True)
    code.write_text("print('ok')", encoding="utf-8")
    assert detection.has_semgrep_content(tmp_path)


def test_has_container_tarballs_respects_depth(tmp_path: Path) -> None:
    shallow = tmp_path / "images" / "one.tar"
    shallow.parent.mkdir(parents=True)
    shallow.write_text("x", encoding="utf-8")
    deep = tmp_path / "a" / "b" / "c" / "d" / "too-deep.tar"
    deep.parent.mkdir(parents=True)
    deep.write_text("x", encoding="utf-8")
    found = detection.has_container_tarballs(tmp_path, max_depth=3)
    assert shallow in found
    assert deep not in found


def test_tar_listing_caches_and_recognizes_formats(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "bundle.tar"
    tar.write_text("x", encoding="utf-8")
    calls: list[list[str]] = []
    cache: dict[tuple[str, int, int], str] = {}

    class _Completed:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    def _fake_run(cmd, capture_output=True, text=True, timeout=30):
        calls.append(cmd)
        return _Completed(0, "manifest.json\nfoo.wrap\n")

    monkeypatch.setattr(detection.subprocess, "run", _fake_run)
    first = detection._tar_listing(tar, cache)
    second = detection._tar_listing(tar, cache)
    assert first == second
    assert len(calls) == 1
    assert detection._tar_is_docker_save(first or "")
    assert detection._tar_has_wrap_files(first or "")


def test_docker_save_image_ref_parsing(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "bundle.tar"
    tar.write_text("x", encoding="utf-8")

    class _Completed:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    monkeypatch.setattr(
        detection.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, json.dumps([{"RepoTags": ["ghcr.io/acme/app:v1"]}])),
    )
    assert detection._docker_save_image_ref(tar) == "ghcr.io/acme/app:v1"


def test_collect_container_sources_handles_wrap_extract_failure(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "bundle.tar"
    tar.write_text("x", encoding="utf-8")

    class _Completed:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    def _fake_run(cmd, capture_output=True, text=True, timeout=30, check=False):
        if cmd[:2] == ["tar", "-tf"]:
            return _Completed(0, "foo.wrap\n")
        if cmd[:2] == ["tar", "-xf"]:
            return _Completed(0, "")
        if cmd[:2] == ["tar", "-xzf"]:
            raise subprocess.CalledProcessError(1, cmd)
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(detection.subprocess, "run", _fake_run)
    sources, extract_dirs = detection.collect_container_sources(tmp_path, temp_dir=tmp_path)
    assert sources == []
    assert len(extract_dirs) == 1


def test_collect_container_sources_respects_exclude(monkeypatch, tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    keep_dir = tmp_path / "keep"
    artifact_dir.mkdir(parents=True)
    keep_dir.mkdir(parents=True)
    tar_skip = artifact_dir / "skip.tar"
    tar_keep = keep_dir / "keep.tar"
    tar_skip.write_text("x", encoding="utf-8")
    tar_keep.write_text("x", encoding="utf-8")

    class _Completed:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    def _fake_run(cmd, capture_output=True, text=True, timeout=30, check=False):
        if cmd[:2] == ["tar", "-tf"]:
            # Both tar files look like docker-save images.
            return _Completed(0, "manifest.json\n")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(detection.subprocess, "run", _fake_run)
    monkeypatch.setattr(detection, "_docker_save_image_ref", lambda *args, **kwargs: None)
    monkeypatch.setattr(detection, "_with_computed_digest", lambda src: src)
    sources, _extract_dirs = detection.collect_container_sources(
        tmp_path,
        temp_dir=tmp_path,
        exclude=["**/artifacts/**"],
    )
    assert len(sources) == 1
    assert sources[0].path == tar_keep


def test_get_oci_image_ref_name_invalid_json(tmp_path: Path) -> None:
    layout = tmp_path / "oci"
    layout.mkdir()
    (layout / "index.json").write_text("{", encoding="utf-8")
    assert detection._get_oci_image_ref_name(layout) is None


def test_images_lock_parsers_without_yaml(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(detection, "yaml", None)
    assert detection._get_imgpkg_images_lock(tmp_path) == {}
    assert detection._get_chart_images_lock(tmp_path) == {}
