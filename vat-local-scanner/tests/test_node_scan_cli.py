from __future__ import annotations

import argparse
from pathlib import Path

from vat_scanner import cli


def _node_args(tmp_path: Path, **overrides):
    base = dict(
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="",
        admin_token="adm",
        reset_keys=False,
        cluster_name="k3s-remote",
        node_name="node-a",
        host_root=tmp_path / "host",
        scan_types="node-stig,node-oval-cve",
        timeout=120,
        verbose=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_cmd_scan_node_ingests_stig_and_oval(monkeypatch, tmp_path: Path) -> None:
    host_root = tmp_path / "host"
    host_root.mkdir()
    (host_root / "etc").mkdir()
    (host_root / "etc" / "os-release").write_text("ID=rhel\nVERSION_ID=9\n", encoding="utf-8")

    monkeypatch.setattr(cli, "run_node_stig", lambda *args, **kwargs: "<xccdf/>")
    monkeypatch.setattr(cli, "run_node_oval_cve", lambda *args, **kwargs: "<oval/>")
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: (args[2], f"{args[2]}-key"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)

    ingest_calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "ingest_openscap_report",
        lambda *args, **kwargs: ingest_calls.append({"parser": "openscap", **kwargs}) or {"ok": 1},
    )
    monkeypatch.setattr(
        cli,
        "ingest_openscap_oval_report",
        lambda *args, **kwargs: ingest_calls.append({"parser": "openscap_oval", **kwargs}) or {"ok": 1},
    )

    assert cli.cmd_scan_node(_node_args(tmp_path, host_root=host_root)) == 0
    assert [call["parser"] for call in ingest_calls] == ["openscap", "openscap_oval"]
    assert [call["asset"] for call in ingest_calls] == [
        "k8s/k3s-remote/node/node-a/host",
        "k8s/k3s-remote/node/node-a/host",
    ]
    assert [call["tag"] for call in ingest_calls] == ["node-stig", "node-oval-cve"]


def test_cmd_scan_node_skips_when_host_root_missing(monkeypatch, tmp_path: Path) -> None:
    calls: list[object] = []
    monkeypatch.setattr(cli, "run_node_stig", lambda *args, **kwargs: calls.append(args) or "<xccdf/>")
    args = _node_args(tmp_path, host_root=tmp_path / "missing", dry_run=True)

    assert cli.cmd_scan_node(args) == 0
    assert calls == []


def _runtime_args(tmp_path: Path, **overrides):
    base = dict(
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="runtime-key",
        admin_token="",
        reset_keys=False,
        cluster_name="k3s-remote",
        node_name="node-a",
        containerd_socket=tmp_path / "containerd.sock",
        containerd_namespace="k8s.io",
        docker_socket=tmp_path / "docker.sock",
        scan_types="image-sca,image-sbom",
        state_file=tmp_path / "runtime-state.json",
        full_rescan_interval_seconds=86400,
        force_full_rescan=True,
        no_snippets=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_runtime_inventory_targets_kubernetes_and_host_containers() -> None:
    doc = {
        "containers": [
            {
                "id": "abc123456789",
                "metadata": {"name": "api"},
                "image": {"image": "registry.example.com/api:v1"},
                "labels": {
                    "io.kubernetes.pod.namespace": "apps",
                    "io.kubernetes.pod.name": "api-abc",
                    "io.kubernetes.container.name": "api",
                },
                "state": "CONTAINER_EXITED",
            },
            {
                "id": "def123456789",
                "metadata": {"name": "kind-control-plane"},
                "image": {"image": "kindest/node:v1.29.0"},
                "labels": {},
                "state": "CONTAINER_RUNNING",
            },
        ]
    }

    targets = cli._runtime_targets_from_crictl(doc, "k3s-remote", "node-a")

    assert targets == [
        {
            "asset": "k8s/k3s-remote/apps/pod/api-abc/api",
            "containerId": "abc123456789",
            "containerName": "api",
            "image": "registry.example.com/api:v1",
            "nodeName": "node-a",
            "state": "CONTAINER_EXITED",
        },
        {
            "asset": "k8s/k3s-remote/node/node-a/runtime/kind-control-plane-def123456789",
            "containerId": "def123456789",
            "containerName": "kind-control-plane",
            "image": "kindest/node:v1.29.0",
            "nodeName": "node-a",
            "state": "CONTAINER_RUNNING",
        },
    ]


def test_runtime_image_store_targets_unreferenced_cri_images() -> None:
    doc = {
        "images": [
            {
                "id": "sha256:111",
                "repoTags": ["kindest/node:v1.29.0"],
                "repoDigests": ["docker.io/kindest/node@sha256:aaa"],
            },
            {
                "id": "sha256:222",
                "repoTags": ["registry.example.com/api:v1"],
                "repoDigests": ["registry.example.com/api@sha256:bbb"],
            },
        ]
    }

    targets = cli._runtime_targets_from_crictl_images(
        doc,
        "k3s-remote",
        "node-a",
        referenced_images={"registry.example.com/api:v1"},
    )

    assert targets == [
        {
            "asset": "k8s/k3s-remote/node/node-a/runtime-image/kindest-node-v1.29.0",
            "containerId": "sha256:111",
            "containerName": "kindest/node:v1.29.0",
            "image": "kindest/node:v1.29.0",
            "nodeName": "node-a",
            "state": "IMAGE_PRESENT",
        }
    ]


def test_docker_runtime_targets_include_containers_and_image_store() -> None:
    container_targets = cli._runtime_targets_from_docker_containers(
        [
            {
                "ID": "abc123456789",
                "Image": "kindest/node:v1.30.0",
                "Names": "kind-control-plane",
                "State": "running",
            }
        ],
        "k3s-remote",
        "node-a",
    )
    image_targets = cli._runtime_targets_from_docker_images(
        [
            {
                "ID": "sha256:def",
                "Repository": "registry",
                "Tag": "2",
                "Digest": "sha256:ccc",
            }
        ],
        "k3s-remote",
        "node-a",
        referenced_images={"kindest/node:v1.30.0"},
    )

    assert container_targets == [
        {
            "asset": "k8s/k3s-remote/node/node-a/docker-container/kind-control-plane-abc123456789",
            "containerId": "abc123456789",
            "containerName": "kind-control-plane",
            "image": "kindest/node:v1.30.0",
            "nodeName": "node-a",
            "state": "running",
        }
    ]
    assert image_targets == [
        {
            "asset": "k8s/k3s-remote/node/node-a/docker-image/registry-2",
            "containerId": "sha256:def",
            "containerName": "registry:2",
            "image": "registry:2",
            "nodeName": "node-a",
            "state": "IMAGE_PRESENT",
        }
    ]


def test_cmd_scan_runtime_ingests_each_runtime_target(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    runtime_doc = {
        "containers": [
            {
                "id": "abc123456789",
                "metadata": {"name": "api"},
                "image": {"image": "registry.example.com/shared:v1"},
                "labels": {
                    "io.kubernetes.pod.namespace": "apps",
                    "io.kubernetes.pod.name": "api-abc",
                    "io.kubernetes.container.name": "api",
                },
                "state": "CONTAINER_RUNNING",
            },
            {
                "id": "def123456789",
                "metadata": {"name": "worker"},
                "image": {"image": "registry.example.com/shared:v1"},
                "labels": {
                    "io.kubernetes.pod.namespace": "apps",
                    "io.kubernetes.pod.name": "worker-def",
                    "io.kubernetes.container.name": "worker",
                },
                "state": "CONTAINER_EXITED",
            },
        ]
    }
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: runtime_doc)
    monkeypatch.setattr(cli, "_load_runtime_images", lambda *args, **kwargs: {"images": []})
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref",
        lambda *args, **kwargs: {"Results": [{"Target": "registry.example.com/shared:v1"}]},
    )
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref_cyclonedx",
        lambda *args, **kwargs: {"components": [{"name": "openssl"}]},
    )

    calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "_ingest_trivy_report_with_retry",
        lambda **kwargs: calls.append({"kind": "trivy", **kwargs}) or {"ok": 1},
    )
    monkeypatch.setattr(
        cli,
        "_ingest_json_report_with_retry",
        lambda **kwargs: calls.append({"kind": "cyclonedx", **kwargs}) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(_runtime_args(tmp_path, containerd_socket=socket_path)) == 0

    trivy_calls = [call for call in calls if call["kind"] == "trivy"]
    assert [call["asset_name"] for call in trivy_calls] == [
        "k8s/k3s-remote/apps/pod/api-abc/api",
        "k8s/k3s-remote/apps/pod/worker-def/worker",
    ]
    assert all(call["image_digest"] is None for call in trivy_calls)


def test_cmd_scan_runtime_ingests_cri_image_store_and_docker_targets(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    docker_socket = tmp_path / "docker.sock"
    docker_socket.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {"images": [{"id": "sha256:kind", "repoTags": ["kindest/node:v1.30.0"]}]},
    )
    monkeypatch.setattr(
        cli,
        "_load_docker_containers",
        lambda *args, **kwargs: [
            {"ID": "abc123456789", "Image": "registry:2", "Names": "kind-registry", "State": "running"}
        ],
    )
    monkeypatch.setattr(
        cli,
        "_load_docker_images",
        lambda *args, **kwargs: [{"ID": "sha256:unused", "Repository": "busybox", "Tag": "1.36"}],
    )
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: {"Results": [{"Target": args[0]}]})
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: None)

    calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "_ingest_trivy_report_with_retry",
        lambda **kwargs: calls.append({"kind": "trivy", **kwargs}) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            containerd_socket=socket_path,
            docker_socket=docker_socket,
            scan_types="image-sca",
        )
    ) == 0

    assert [call["asset_name"] for call in calls] == [
        "k8s/k3s-remote/node/node-a/docker-image/busybox-1.36",
        "k8s/k3s-remote/node/node-a/runtime-image/kindest-node-v1.30.0",
        "k8s/k3s-remote/node/node-a/docker-container/kind-registry-abc123456789",
    ]
