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
    host_run = Path("/tmp/does-not-exist")
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

    targets = cli._runtime_targets_from_crictl(
        doc,
        "k3s-remote",
        "node-a",
        containerd_socket=host_run / "containerd.sock",
    )

    assert targets == [
        {
            "asset": "registry.example.com/api:v1",
            "containerId": "abc123456789",
            "containerName": "api",
            "image": "registry.example.com/api:v1",
            "kubernetes": {
                "cluster": "k3s-remote",
                "namespace": "apps",
                "podName": "api-abc",
                "containerName": "api",
                "nodeName": "node-a",
            },
            "nodeName": "node-a",
            "runtimeSource": "containerd",
            "state": "CONTAINER_EXITED",
        },
        {
            "asset": "kindest/node:v1.29.0",
            "containerId": "def123456789",
            "containerName": "kind-control-plane",
            "image": "kindest/node:v1.29.0",
            "nodeName": "node-a",
            "runtimeSource": "containerd",
            "state": "CONTAINER_RUNNING",
        },
    ]


def test_runtime_inventory_targets_include_containerd_rootfs(tmp_path: Path) -> None:
    socket_path = tmp_path / "host" / "run" / "k3s" / "containerd" / "containerd.sock"
    rootfs = (
        tmp_path
        / "host"
        / "run"
        / "k3s"
        / "containerd"
        / "io.containerd.runtime.v2.task"
        / "k8s.io"
        / "abc123456789"
        / "rootfs"
    )
    rootfs.mkdir(parents=True)
    socket_path.write_text("", encoding="utf-8")

    targets = cli._runtime_targets_from_crictl(
        {
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
                    "state": "CONTAINER_RUNNING",
                }
            ]
        },
        "k3s-remote",
        "node-a",
        containerd_socket=socket_path,
    )

    assert targets[0]["rootfsPath"] == str(rootfs)
    assert targets[0]["asset"] == "registry.example.com/api:v1"
    assert targets[0]["kubernetes"]["podName"] == "api-abc"


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
            "asset": "kindest/node:v1.29.0",
            "containerId": "sha256:111",
            "containerName": "kindest/node:v1.29.0",
            "image": "kindest/node:v1.29.0",
            "nodeName": "node-a",
            "runtimeSource": "containerd",
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
            "asset": "kindest/node:v1.30.0",
            "containerId": "abc123456789",
            "containerName": "kind-control-plane",
            "image": "kindest/node:v1.30.0",
            "nodeName": "node-a",
            "runtimeSource": "docker",
            "state": "running",
        }
    ]
    assert image_targets == [
        {
            "asset": "registry:2",
            "containerId": "sha256:def",
            "containerName": "registry:2",
            "image": "registry:2",
            "nodeName": "node-a",
            "runtimeSource": "docker",
            "state": "IMAGE_PRESENT",
        }
    ]


def test_docker_runtime_targets_include_local_rootfs(monkeypatch, tmp_path: Path) -> None:
    docker_socket = tmp_path / "docker.sock"
    docker_socket.write_text("", encoding="utf-8")
    host_root = tmp_path / "host"
    rootfs = host_root / "var/lib/docker/overlay2/abc/merged"
    rootfs.mkdir(parents=True)

    class _Result:
        returncode = 0
        stdout = '[{"GraphDriver":{"Data":{"MergedDir":"/var/lib/docker/overlay2/abc/merged"}}}]'
        stderr = ""

    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: _Result())

    targets = cli._runtime_targets_from_docker_containers(
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
        docker_socket=docker_socket,
        docker_host_root=host_root,
    )

    assert targets[0]["rootfsPath"] == str(rootfs)


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
    trivy_image_sources: list[str | None] = []
    cyclonedx_image_sources: list[str | None] = []

    def fake_trivy_image_ref(*args, **kwargs):
        trivy_image_sources.append(kwargs.get("image_src"))
        return {"Results": [{"Target": "registry.example.com/shared:v1"}]}

    def fake_trivy_image_ref_cyclonedx(*args, **kwargs):
        cyclonedx_image_sources.append(kwargs.get("image_src"))
        return {"components": [{"name": "openssl"}]}

    monkeypatch.setattr(cli, "run_trivy_image_ref", fake_trivy_image_ref)
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", fake_trivy_image_ref_cyclonedx)

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
    assert [call["asset_name"] for call in trivy_calls] == ["registry.example.com/shared:v1"]
    assert all(call["image_digest"] is None for call in trivy_calls)
    assert trivy_image_sources == ["containerd"]
    assert cyclonedx_image_sources == ["containerd"]


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
        "busybox:1.36",
        "kindest/node:v1.30.0",
        "registry:2",
    ]


def test_cmd_scan_runtime_ingests_container_stig_without_docker_socket(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    docker_socket = tmp_path / "missing-docker.sock"
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {"images": [{"id": "sha256:kind", "repoTags": ["kindest/node:v1.30.0"]}]},
    )
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "run_stig_image_ref", lambda *args, **kwargs: "<xccdf/>")

    calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "ingest_openscap_report",
        lambda *args, **kwargs: calls.append(kwargs) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            containerd_socket=socket_path,
            docker_socket=docker_socket,
            scan_types="container-stig",
        )
    ) == 0

    assert calls == [
        {
            "asset": "kindest/node:v1.30.0",
            "tag": "v1.30.0",
            "image_digest": None,
            "idempotency_key": "openscap:kindest/node:v1.30.0:kindest/node:v1.30.0",
        }
    ]


def test_cmd_scan_runtime_prefers_containerd_rootfs_for_container_stig(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "host" / "run" / "k3s" / "containerd" / "containerd.sock"
    rootfs = (
        tmp_path
        / "host"
        / "run"
        / "k3s"
        / "containerd"
        / "io.containerd.runtime.v2.task"
        / "k8s.io"
        / "abc123456789"
        / "rootfs"
    )
    rootfs.mkdir(parents=True)
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "_load_runtime_containers",
        lambda *args, **kwargs: {
            "containers": [
                {
                    "id": "abc123456789",
                    "metadata": {"name": "api"},
                    "image": {"image": "ghcr.io/private/app:v1"},
                    "labels": {
                        "io.kubernetes.pod.namespace": "apps",
                        "io.kubernetes.pod.name": "api-abc",
                        "io.kubernetes.container.name": "api",
                    },
                    "state": "CONTAINER_RUNNING",
                }
            ]
        },
    )
    monkeypatch.setattr(cli, "_load_runtime_images", lambda *args, **kwargs: {"images": []})
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])

    rootfs_calls: list[Path] = []
    monkeypatch.setattr(
        cli,
        "run_stig_rootfs",
        lambda rootfs_path, *args, **kwargs: rootfs_calls.append(Path(rootfs_path)) or "<xccdf/>",
    )
    monkeypatch.setattr(
        cli,
        "run_stig_image_ref",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("remote pull should not be used")),
    )

    calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "ingest_openscap_report",
        lambda *args, **kwargs: calls.append(kwargs) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            containerd_socket=socket_path,
            docker_socket=tmp_path / "missing-docker.sock",
            scan_types="container-stig",
        )
    ) == 0

    assert rootfs_calls == [rootfs]
    assert calls[0]["asset"] == "ghcr.io/private/app:v1"


def test_cmd_scan_runtime_counts_missing_container_stig_as_failure(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {"images": [{"id": "sha256:kind", "repoTags": ["private/app:v1"]}]},
    )
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "run_stig_image_ref", lambda *args, **kwargs: None)

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            containerd_socket=socket_path,
            docker_socket=tmp_path / "missing-docker.sock",
            scan_types="container-stig",
            fail_on_error=True,
        )
    ) == 1


def test_cmd_scan_runtime_prefers_parser_specific_openscap_key(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {"images": [{"id": "sha256:kind", "repoTags": ["kindest/node:v1.30.0"]}]},
    )
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "run_stig_image_ref", lambda *args, **kwargs: "<xccdf/>")
    ensure_calls: list[dict] = []

    def _ensure_source(*args, **kwargs):
        ensure_calls.append(kwargs)
        return args[2], ("openscap-key" if kwargs.get("regenerate_key") else None)

    monkeypatch.setattr(cli, "ensure_source", _ensure_source)
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)

    keys: list[str] = []
    monkeypatch.setattr(
        cli,
        "ingest_openscap_report",
        lambda vat_url, key, *args, **kwargs: keys.append(key) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            api_key="runtime-key",
            admin_token="adm",
            containerd_socket=socket_path,
            docker_socket=tmp_path / "missing-docker.sock",
            scan_types="container-stig",
        )
    ) == 0

    assert keys == ["openscap-key"]
    assert [call.get("regenerate_key") for call in ensure_calls] == [False, True]


def test_cmd_scan_runtime_summarizes_scanner_failures_without_error_spam(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {
            "images": [
                {
                    "id": "sha256:kind",
                    "repoTags": ["kindest/node:v1.30.0"],
                }
            ]
        },
    )
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: None)

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            api_key="runtime-key",
            admin_token="",
            containerd_socket=socket_path,
            docker_socket=tmp_path / "missing-docker.sock",
            scan_types="image-sca,image-sbom",
        )
    ) == 0

    captured = capsys.readouterr()
    assert "Runtime scan complete." in captured.out
    assert "scannerFailures=2" in captured.out
    assert "ERROR: Trivy runtime image scan failed" not in captured.err
    assert "ERROR: Trivy CycloneDX runtime image scan failed" not in captured.err


def test_cmd_scan_runtime_ingests_container_stig_when_trivy_fails(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / "containerd.sock"
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli, "_load_runtime_containers", lambda *args, **kwargs: {"containers": []})
    monkeypatch.setattr(
        cli,
        "_load_runtime_images",
        lambda *args, **kwargs: {"images": [{"id": "sha256:kind", "repoTags": ["kindest/node:v1.30.0"]}]},
    )
    monkeypatch.setattr(cli, "_load_docker_containers", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "_load_docker_images", lambda *args, **kwargs: [])
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_stig_image_ref", lambda *args, **kwargs: "<xccdf/>")

    calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "ingest_openscap_report",
        lambda *args, **kwargs: calls.append(kwargs) or {"ok": 1},
    )

    assert cli.cmd_scan_runtime(
        _runtime_args(
            tmp_path,
            containerd_socket=socket_path,
            docker_socket=tmp_path / "missing-docker.sock",
            scan_types="image-sca,container-stig",
        )
    ) == 0

    assert calls
    assert calls[0]["tag"] == "v1.30.0"
