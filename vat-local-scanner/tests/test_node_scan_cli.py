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
