from __future__ import annotations

import argparse
import base64
import gzip
import json
from pathlib import Path

from vat_scanner import cli


def test_cmd_scan_k8s_inventory_scans_changed_objects(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "default",
                        "kind": "Deployment",
                        "name": "api",
                        "resourceVersion": "11",
                        "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
                    },
                    {
                        "namespace": "default",
                        "kind": "Role",
                        "name": "reader",
                        "resourceVersion": "12",
                        "manifest": "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: reader\n",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    scan_dirs: list[Path] = []
    ingest_calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "run_trivy_fs",
        lambda folder, **kwargs: scan_dirs.append(Path(folder)) or {"Results": [{"Target": str(folder)}]},
    )
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: ingest_calls.append({"report": args[2], **kwargs}) or {"ok": 1})
    monkeypatch.setattr(cli, "run_gitleaks", lambda *args, **kwargs: None)

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    assert len(scan_dirs) == 2
    # Config/RBAC posture scopes to one asset per namespace, not one per object.
    assert [call["asset"] for call in ingest_calls] == [
        "k8s/k3s-remote/default",
        "k8s/k3s-remote/default",
    ]
    assert [call["tag"] for call in ingest_calls] == ["k8s-config", "rbac"]


def test_cmd_scan_k8s_inventory_skips_unchanged_objects(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    state_path = tmp_path / "k8s-state.json"
    manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "default",
                        "kind": "Deployment",
                        "name": "api",
                        "resourceVersion": "11",
                        "manifest": manifest,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    state_path.write_text(
        json.dumps(
            {
                "lastFullScanAt": "2999-01-01T00:00:00Z",
                "objects": {
                    "default/Deployment/api": {
                        "signature": cli._k8s_inventory_item_signature(
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "resourceVersion": "11",
                                "manifest": manifest,
                            }
                        )
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    scan_calls: list[Path] = []
    monkeypatch.setattr(cli, "run_trivy_fs", lambda folder, **kwargs: scan_calls.append(Path(folder)) or {"Results": []})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=state_path,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    assert scan_calls == []


def test_cmd_scan_k8s_inventory_checkpoints_after_each_success(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    state_path = tmp_path / "k8s-state.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "default",
                        "kind": "Deployment",
                        "name": "api",
                        "resourceVersion": "11",
                        "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
                    },
                    {
                        "namespace": "default",
                        "kind": "Role",
                        "name": "reader",
                        "resourceVersion": "12",
                        "manifest": "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: reader\n",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    calls = {"count": 0}

    def _scan_or_interrupt(folder, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise SystemExit("simulated pod termination")
        return {"Results": [{"Target": str(folder)}]}

    monkeypatch.setattr(cli, "run_trivy_fs", _scan_or_interrupt)
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: {"ok": 1})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=state_path,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    try:
        cli.cmd_scan_k8s_inventory(args)
    except SystemExit:
        pass

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert "default/Deployment/api" in state.get("objects", {})
    assert "default/Role/reader" not in state.get("objects", {})


def test_cmd_scan_k8s_inventory_reads_compressed_inventory(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json.gz.b64"
    payload = json.dumps(
        {
            "items": [
                {
                    "namespace": "default",
                    "kind": "Deployment",
                    "name": "api",
                    "resourceVersion": "11",
                    "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
                }
            ]
        }
    ).encode("utf-8")
    inventory_path.write_text(base64.b64encode(gzip.compress(payload)).decode("ascii"), encoding="utf-8")
    scan_calls: list[Path] = []
    monkeypatch.setattr(cli, "run_trivy_fs", lambda folder, **kwargs: scan_calls.append(Path(folder)) or {"Results": []})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=True,
        fail_on_error=False,
        vat_url="",
        api_key="",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    assert len(scan_calls) == 1


def test_cmd_scan_k8s_inventory_uses_admin_token_to_refresh_key(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "default",
                        "kind": "Role",
                        "name": "reader",
                        "resourceVersion": "12",
                        "manifest": "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: reader\n",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ensure_called = {"value": False}
    ingest_keys: list[str] = []
    monkeypatch.setattr(cli, "run_trivy_fs", lambda folder, **kwargs: {"Results": []})
    monkeypatch.setattr(cli, "run_gitleaks", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ensure_called.__setitem__("value", True) or ("trivy", "fresh-trivy-key"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "ingest_report", lambda base_url, api_key, report, **kwargs: ingest_keys.append(api_key) or {"ok": 1})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="direct-key",
        admin_token="adm",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    assert ensure_called["value"] is True
    assert ingest_keys == ["fresh-trivy-key"]
