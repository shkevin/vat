"""Tests for deterministic container digest from on-disk artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

from vat_scanner.container_digest import (
    compute_container_image_digest,
    docker_save_config_digest_from_tar,
    oci_image_manifest_digest_from_layout,
)


def _hash256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_docker_save_config_digest_from_minimal_tar(tmp_path: Path) -> None:
    config_body = b'{"architecture":"amd64","config":{"Labels":{}}}'
    expected = "sha256:" + hashlib.sha256(config_body).hexdigest()
    tar_path = tmp_path / "img.tar"
    manifest = [{"Config": "config.json", "RepoTags": ["repo/img:latest"], "Layers": []}]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        mjson = json.dumps(manifest).encode()
        ti = tarfile.TarInfo(name="manifest.json")
        ti.size = len(mjson)
        tf.addfile(ti, io.BytesIO(mjson))
        ti2 = tarfile.TarInfo(name="config.json")
        ti2.size = len(config_body)
        tf.addfile(ti2, io.BytesIO(config_body))
    tar_path.write_bytes(buf.getvalue())
    assert docker_save_config_digest_from_tar(tar_path) == expected
    assert compute_container_image_digest(tar_path, "docker-save") == expected


def test_oci_layout_manifest_digest(tmp_path: Path) -> None:
    layout = tmp_path / "oci"
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    manifest_body = (
        b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",'
        b'"config":{"digest":"sha256:0"}}\n'
    )
    digest = "sha256:" + _hash256_hex(manifest_body)
    hex_full = digest[7:]
    (blobs / hex_full).write_bytes(manifest_body)
    idx = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
                "size": len(manifest_body),
            }
        ],
    }
    (layout / "index.json").write_text(json.dumps(idx), encoding="utf-8")
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}\n', encoding="utf-8")
    assert oci_image_manifest_digest_from_layout(layout) == digest
    assert compute_container_image_digest(layout, "oci-layout") == digest


def test_normalize_trivy_canonical_overrides_trivy_report() -> None:
    from vat_scanner.scanners import normalize

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
        "bundle",
        source_image="lbl",
        image_ref="ghcr.io/acme/my-app:latest",
        canonical_image_digest="sha256:" + "ab" * 32,
    )
    assert (
        out["Results"][0][normalize.VAT_CONTAINER_DIGEST_KEY]
        == "sha256:" + "ab" * 32
    )
