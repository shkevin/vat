from __future__ import annotations

import argparse
import base64
import copy
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from vat_scanner.config import ScannerConfig
from vat_scanner.scanners.runners import ScannerNotFoundError
from vat_scanner import cli, scan


def test_scan_helpers_basic(capsys) -> None:
    assert scan._sanitize_asset_name("a b/c") == "a-b-c"
    assert scan._fmt_elapsed(2.34).endswith("s")
    assert "m" in scan._fmt_elapsed(61.0)

    conf = ScannerConfig(verbose=True)
    scan._verbose(conf, "hello")
    out = capsys.readouterr()
    assert "hello" in out.err


def test_apply_cyclonedx_container_ref() -> None:
    doc = {"components": [{"name": "openssl"}]}
    out = scan._apply_cyclonedx_container_ref(doc, "ghcr.io/acme/app:v1")
    assert out["components"][0]["properties"][0]["name"] == "vat:container_ref"
    # idempotent when already present
    out2 = scan._apply_cyclonedx_container_ref(out, "ghcr.io/acme/app:v1")
    props = out2["components"][0]["properties"]
    assert len([p for p in props if p["name"] == "vat:container_ref"]) == 1


def test_run_scan_raises_for_bad_path_and_trivy_failure(monkeypatch, tmp_path: Path) -> None:
    cfg = ScannerConfig(asset="x")
    with pytest.raises(ValueError):
        scan.run_scan(tmp_path / "missing", cfg)

    def _boom(*args, **kwargs):
        raise ScannerNotFoundError("trivy not found")

    monkeypatch.setattr(scan, "run_trivy_fs", _boom)
    with pytest.raises(RuntimeError):
        scan.run_scan(tmp_path, cfg)


def test_run_scan_full_happy_path(monkeypatch, tmp_path: Path) -> None:
    cfg = ScannerConfig(
        asset="bundle",
        scan_types=["dependencies", "container", "stig", "oval_cve", "code", "secrets"],
        verbose=True,
        scan_timeout_ms=120000,
    )
    src = SimpleNamespace(format="docker-save", path=tmp_path / "img.tar", label="img-a", image_ref="ghcr.io/acme/app:v1")
    src.path.write_text("x", encoding="utf-8")

    monkeypatch.setattr(scan, "run_trivy_fs", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr(scan, "collect_container_sources", lambda *args, **kwargs: ([src], []))
    monkeypatch.setattr(scan, "run_trivy_image", lambda *args, **kwargs: {"Results": [{"Target": "container"}]})
    monkeypatch.setattr(scan, "run_trivy_oci_layout", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan, "run_stig_image", lambda *args, **kwargs: "<xccdf/>")
    monkeypatch.setattr(scan, "run_stig_oci_layout", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan, "run_oval_cve_image", lambda *args, **kwargs: ("<oval/>", False))
    monkeypatch.setattr(scan, "run_oval_cve_oci_layout", lambda *args, **kwargs: (None, False))
    monkeypatch.setattr(scan, "run_trivy_fs_cyclonedx", lambda *args, **kwargs: {"components": [{"name": "openssl"}]})
    monkeypatch.setattr(
        scan,
        "run_trivy_image_cyclonedx",
        lambda *args, **kwargs: {"components": [{"name": "glibc"}]},
    )
    monkeypatch.setattr(scan, "run_trivy_oci_layout_cyclonedx", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan, "has_grype_content", lambda *args, **kwargs: True)
    monkeypatch.setattr(scan, "has_npm_content", lambda *args, **kwargs: True)
    monkeypatch.setattr(scan, "has_pip_content", lambda *args, **kwargs: True)
    monkeypatch.setattr(scan, "has_semgrep_content", lambda *args, **kwargs: True)
    monkeypatch.setattr(scan, "run_grype", lambda *args, **kwargs: {"matches": []})
    monkeypatch.setattr(scan, "run_npm_audit", lambda *args, **kwargs: {"vulnerabilities": {"x": {"severity": "low"}}})
    monkeypatch.setattr(scan, "run_pip_audit", lambda *args, **kwargs: [{"name": "flask", "vulns": []}])
    monkeypatch.setattr(scan, "run_semgrep", lambda *args, **kwargs: {"results": [{"path": "a.py"}]})
    monkeypatch.setattr(scan, "run_gitleaks", lambda *args, **kwargs: [{"File": "secret.env"}])
    monkeypatch.setattr(scan, "normalize_trivy", lambda report, *args, **kwargs: report)
    monkeypatch.setattr(scan, "normalize_grype", lambda report, *args, **kwargs: report)
    monkeypatch.setattr(scan, "normalize_gitleaks", lambda report, *args, **kwargs: report)
    monkeypatch.setattr(scan, "enrich_reports", lambda *args, **kwargs: None)

    seen: list[str] = []
    reports = scan.run_scan(tmp_path, cfg, on_report=lambda parser, report: seen.append(parser))
    assert "trivy" in reports
    assert "cyclonedx" in reports
    assert "openscap" in reports
    assert "openscap_oval" in reports
    assert "gitleaks" in reports
    assert "semgrep" in reports
    assert "trivy" in seen
    assert "cyclonedx" in seen


def test_run_scan_dependencies_zero_components_raises(monkeypatch, tmp_path: Path) -> None:
    cfg = ScannerConfig(asset="bundle", scan_types=["dependencies"])
    monkeypatch.setattr(scan, "run_trivy_fs_cyclonedx", lambda *args, **kwargs: {"components": []})
    monkeypatch.setattr(scan, "collect_container_sources", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(scan, "has_grype_content", lambda *args, **kwargs: False)
    monkeypatch.setattr(scan, "has_npm_content", lambda *args, **kwargs: False)
    monkeypatch.setattr(scan, "has_pip_content", lambda *args, **kwargs: False)
    with pytest.raises(RuntimeError):
        scan.run_scan(tmp_path, cfg)


def test_cli_parse_and_merge_scan_types() -> None:
    assert "code" in cli._parse_scan_types("code,dependencies")
    assert len(cli._parse_scan_types("")) == len(cli.ALL_SCAN_TYPES)


def test_cli_merge_scan_cli() -> None:
    cfg = ScannerConfig(asset="a")
    args = argparse.Namespace(
        vat_url="https://vat",
        api_key="k",
        admin_token="adm",
        asset="b",
        asset_mode="single",
        scan_types="code,secrets",
        exclude=["dist/**"],
        dry_run=True,
        gating_mode="release",
        fail_on="high",
        base_commit_id="b1",
        head_commit_id="h1",
        scan_timeout=123,
        disable_artifact_scanning=True,
        reset_keys=True,
        gating_result_output="out.json",
        no_snippets=True,
        sarif_output="out.sarif",
        temp_dir="/tmp/x",
        debug=True,
        dev=False,
        verbose=True,
        tag="tag1",
        save_openscap_xml="/tmp/xml",
    )
    merged = cli._merge_scan_cli(cfg, args)
    assert merged.asset == "b"
    assert merged.asset_mode == "single"
    assert merged.dry_run is True
    assert merged.verbose is True


def test_cli_run_gating_writes_output(tmp_path: Path) -> None:
    cfg = ScannerConfig(fail_on="high", gating_mode="release")
    args = argparse.Namespace(gating_result_output=str(tmp_path / "gating.json"))
    reports = {"trivy": {"Results": [{"Target": "a.py", "Vulnerabilities": [{"Severity": "high"}]}]}}
    code = cli._run_gating(reports, tmp_path, cfg, args)
    assert code == 1
    out = json.loads((tmp_path / "gating.json").read_text(encoding="utf-8"))
    assert out["fail"] is True


def test_cli_push_report_variants(monkeypatch) -> None:
    calls = {"json": 0, "oscap": 0, "oval": 0}
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: calls.__setitem__("json", calls["json"] + 1) or {"ok": 1})
    monkeypatch.setattr(cli, "ingest_openscap_report", lambda *args, **kwargs: calls.__setitem__("oscap", calls["oscap"] + 1) or {"ok": 1})
    monkeypatch.setattr(cli, "ingest_openscap_oval_report", lambda *args, **kwargs: calls.__setitem__("oval", calls["oval"] + 1) or {"ok": 1})

    cli._push_report("u", "k", "openscap", [("<xml/>", "img", "ref")], asset="bundle")
    cli._push_report("u", "k", "openscap_oval", [("<xml/>", "img", "ref")], asset="bundle")
    cli._push_report("u", "k", "cyclonedx", [({"components": []}, "img", "ref")], asset="bundle")
    cli._push_report("u", "k", "trivy", {"Results": []}, asset="bundle")

    assert calls["json"] >= 2
    assert calls["oscap"] == 1
    assert calls["oval"] == 1


def test_cli_cmd_config_validate_and_version(monkeypatch, tmp_path: Path, capsys) -> None:
    cfg = tmp_path / "vat-scanner.yaml"
    cfg.write_text("scan_types: [code]\n", encoding="utf-8")
    args = argparse.Namespace(path=str(tmp_path), config_path=None)
    assert cli.cmd_config_validate(args) == 0

    bad_cfg = tmp_path / ".vat-scanner.yaml"
    bad_cfg.write_text("scan_types: invalid\n", encoding="utf-8")
    args_bad = argparse.Namespace(path=str(tmp_path), config_path=bad_cfg)
    assert cli.cmd_config_validate(args_bad) == 1

    assert cli.cmd_version(argparse.Namespace()) == 0
    out = capsys.readouterr()
    assert "vat-scan" in out.out


def test_cli_main_dispatch(monkeypatch) -> None:
    monkeypatch.setattr(cli, "cmd_version", lambda args: 0)
    argv = ["vat-scan", "version"]
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0


def _scan_args(path: Path, **overrides):
    base = dict(
        paths=[str(path)],
        config_path=None,
        vat_url="",
        api_key="",
        admin_token="",
        asset=None,
        asset_mode=None,
        tag=None,
        scan_types="",
        exclude=[],
        dry_run=True,
        gating_mode=None,
        fail_on=None,
        base_commit_id=None,
        head_commit_id=None,
        gating_result_output=None,
        scan_timeout=1000,
        disable_artifact_scanning=False,
        no_snippets=False,
        sarif_output=None,
        reset_keys=False,
        temp_dir=None,
        debug=False,
        dev=False,
        verbose=False,
        save_openscap_xml=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_cmd_scan_dry_run_single_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"trivy": {"Results": []}}, 0))
    args = _scan_args(tmp_path, dry_run=True)
    assert cli.cmd_scan(args) == 0


def test_cmd_scan_non_dry_requires_vat_and_token(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"trivy": {"Results": []}}, 0))
    args = _scan_args(tmp_path, dry_run=False)
    assert cli.cmd_scan(args) == 1


def test_cmd_scan_single_path_push(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"trivy": {"Results": []}}, 0))
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ("trivy", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_push_report", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "enrich_reports", lambda *args, **kwargs: None)
    args = _scan_args(tmp_path, dry_run=False, vat_url="https://vat", admin_token="adm")
    assert cli.cmd_scan(args) == 0


def test_cmd_scan_no_snippets_does_not_reenrich_pushed_report(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "secret.env").write_text("token=SECRET\n", encoding="utf-8")
    report = {
        "findings": [
            {
                "File": "secret.env",
                "StartLine": 1,
                "Secret": "SECRET",
            }
        ]
    }
    pushed_reports: list[dict] = []

    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"gitleaks": copy.deepcopy(report)}, 0))
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ("gitleaks", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        cli,
        "_push_report",
        lambda _url, _key, _parser, payload, **_kwargs: pushed_reports.append(payload) or None,
    )

    args = _scan_args(
        tmp_path,
        dry_run=False,
        vat_url="https://vat",
        admin_token="adm",
        no_snippets=True,
    )

    assert cli.cmd_scan(args) == 0
    finding = pushed_reports[0]["findings"][0]
    assert "Secret" not in finding
    assert "Content" not in finding


def test_cmd_scan_multi_path_push_and_runtime_error(monkeypatch, tmp_path: Path) -> None:
    p1 = tmp_path / "a"
    p2 = tmp_path / "b"
    p1.mkdir()
    p2.mkdir()
    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ("trivy", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: "k")
    monkeypatch.setattr(cli, "_push_report", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "enrich_reports", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "strip_snippets", lambda report: report)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"trivy": {"Results": []}}, 0))
    args = _scan_args(p1, dry_run=False, vat_url="https://vat", admin_token="adm")
    args.paths = [str(p1), str(p2)]
    assert cli.cmd_scan(args) == 0

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "_scan_one_path", _raise)
    assert cli.cmd_scan(args) == 1


def test_cmd_scan_archive_paths(monkeypatch, tmp_path: Path) -> None:
    archive_path = tmp_path / "bundle.tar"
    archive_path.write_text("x", encoding="utf-8")
    extracted = tmp_path / "extracted"
    extracted.mkdir()

    args = argparse.Namespace(
        archives=[str(archive_path)],
        config_path=None,
        vat_url="https://vat",
        api_key="",
        admin_token="adm",
        asset=None,
        asset_mode=None,
        tag=None,
        scan_types="",
        exclude=[],
        dry_run=True,
        gating_mode=None,
        fail_on=None,
        base_commit_id=None,
        head_commit_id=None,
        gating_result_output=None,
        scan_timeout=1000,
        disable_artifact_scanning=False,
        no_snippets=False,
        sarif_output=None,
        reset_keys=False,
        temp_dir=str(tmp_path / "tmp"),
        debug=False,
        dev=False,
        verbose=False,
        save_openscap_xml=None,
    )
    monkeypatch.setattr(cli, "find_config_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "is_archive", lambda p: True)
    monkeypatch.setattr(cli, "extract_archive", lambda *args, **kwargs: extracted)
    monkeypatch.setattr(cli, "_scan_one_path", lambda *args, **kwargs: ({"trivy": {"Results": []}}, 0))
    monkeypatch.setattr(cli, "remove_extracted", lambda *args, **kwargs: None)
    assert cli.cmd_scan_archive(args) == 0

    args.dry_run = False
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ("trivy", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: "k")
    monkeypatch.setattr(cli, "_push_report", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "enrich_reports", lambda *args, **kwargs: None)
    assert cli.cmd_scan_archive(args) == 0


def test_cmd_scan_image_branches(monkeypatch, tmp_path: Path) -> None:
    args = argparse.Namespace(
        image="ghcr.io/acme/app:v1",
        asset=None,
        dry_run=True,
        no_snippets=False,
        sarif_output=None,
        reset_keys=False,
        vat_url="",
        admin_token="",
        tag=None,
        image_digest=None,
    )
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr(cli, "normalize_trivy", lambda report, *args, **kwargs: report)
    assert cli.cmd_scan_image(args) == 0

    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: None)
    assert cli.cmd_scan_image(args) == 1

    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: {"Results": []})
    args.dry_run = False
    assert cli.cmd_scan_image(args) == 1

    args.vat_url = "https://vat"
    args.api_key = "direct-key"
    args.admin_token = "adm"
    args.image_digest = "sha256:abc123"
    ensure_called = {"value": False}
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ensure_called.__setitem__("value", True) or ("trivy", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: "k")
    ingest_kwargs = {}
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: ingest_kwargs.update(kwargs) or {"ok": 1})
    assert cli.cmd_scan_image(args) == 0
    assert ensure_called["value"] is False
    assert ingest_kwargs["image_digest"] == "sha256:abc123"


def test_cmd_scan_inventory_scans_image_once_and_ingests_all_targets(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc123",
                        "targets": [
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            },
                            {
                                "namespace": "other",
                                "kind": "Deployment",
                                "name": "worker",
                                "containerName": "api",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    scan_calls = []
    ingest_calls = []
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref",
        lambda image, timeout=120, **kwargs: scan_calls.append(image) or {"Results": [{"Target": image}]},
    )
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: ingest_calls.append(kwargs) or {"ok": 1})

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
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert scan_calls == ["registry.example.com/api:v1"]
    assert [c["asset"] for c in ingest_calls] == ["registry.example.com/api:v1"]
    assert [c["tag"] for c in ingest_calls] == ["v1"]
    assert [c["image_digest"] for c in ingest_calls] == ["sha256:abc123"]


def test_cmd_scan_inventory_can_ingest_image_sca_and_sbom(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc123",
                        "targets": [
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sca_calls: list[str] = []
    sbom_calls: list[str] = []
    ingest_calls: list[dict] = []
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref",
        lambda image, timeout=120, **kwargs: sca_calls.append(image) or {"Results": [{"Target": image}]},
    )
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref_cyclonedx",
        lambda image, timeout=180, **kwargs: sbom_calls.append(image) or {"components": [{"name": "openssl"}]},
        raising=False,
    )
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: ingest_calls.append({"report": args[2], **kwargs}) or {"ok": 1})

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
        scan_types="image-sca,image-sbom",
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert sca_calls == ["registry.example.com/api:v1"]
    assert sbom_calls == ["registry.example.com/api:v1"]
    assert [call["asset"] for call in ingest_calls] == [
        "registry.example.com/api:v1",
        "registry.example.com/api:v1",
    ]
    assert [call["image_digest"] for call in ingest_calls] == [
        "sha256:abc123",
        "sha256:abc123",
    ]
    assert ingest_calls[0]["report"].get("Results") is not None
    assert ingest_calls[1]["report"].get("components") == [{"name": "openssl"}]


def test_temporary_registry_auth_config_merges_pull_secrets(monkeypatch, tmp_path: Path) -> None:
    item = {
        "targets": [
            {
                "namespace": "apps",
                "imagePullSecrets": ["harbor-creds"],
            }
        ]
    }
    docker_config = {
        "auths": {
            "harbor.example.com": {
                "auth": "dXNlcjpwYXNz",
            }
        }
    }
    secret = {
        "type": "kubernetes.io/dockerconfigjson",
        "data": {
            ".dockerconfigjson": base64.b64encode(json.dumps(docker_config).encode("utf-8")).decode("ascii")
        },
    }
    monkeypatch.setattr(cli, "_fetch_kubernetes_secret", lambda namespace, name: secret)

    with cli._temporary_registry_auth_config(item, temp_base=tmp_path) as docker_config_path:
        assert docker_config_path is not None
        config_path = docker_config_path / "config.json"
        assert json.loads(config_path.read_text(encoding="utf-8")) == docker_config


def test_temporary_registry_auth_config_uses_fallback_secret_names(
    monkeypatch, tmp_path: Path
) -> None:
    item = {
        "targets": [
            {
                "namespace": "apps",
                "kind": "Deployment",
                "name": "api",
                "containerName": "api",
            }
        ]
    }
    docker_config = {
        "auths": {
            "harbor.example.com": {
                "auth": "dXNlcjpwYXNz",
            }
        }
    }
    secret = {
        "type": "kubernetes.io/dockerconfigjson",
        "data": {
            ".dockerconfigjson": base64.b64encode(json.dumps(docker_config).encode("utf-8")).decode("ascii")
        },
    }
    fetched: list[tuple[str, str]] = []

    def fake_fetch(namespace: str, name: str) -> dict:
        fetched.append((namespace, name))
        return secret

    monkeypatch.setenv("VAT_INVENTORY_FALLBACK_IMAGE_PULL_SECRET_NAMES", "harbor-creds")
    monkeypatch.setattr(cli, "_fetch_kubernetes_secret", fake_fetch)

    with cli._temporary_registry_auth_config(item, temp_base=tmp_path) as docker_config_path:
        assert docker_config_path is not None
        config_path = docker_config_path / "config.json"
        assert json.loads(config_path.read_text(encoding="utf-8")) == docker_config

    assert fetched == [("apps", "harbor-creds")]


def test_inventory_signature_includes_pull_secret_references() -> None:
    base = {
        "image": "harbor.example.com/apps/api:v1",
        "targets": [{"namespace": "apps", "kind": "Deployment", "name": "api", "containerName": "api"}],
    }
    with_secret = copy.deepcopy(base)
    with_secret["targets"][0]["imagePullSecrets"] = ["harbor-creds"]

    assert cli._inventory_item_signature(base) != cli._inventory_item_signature(with_secret)


def test_image_ref_tag_extracts_only_real_image_tags() -> None:
    assert cli._image_ref_tag("registry.example.com:5000/apps/api:v1") == "v1"
    assert cli._image_ref_tag("registry.example.com/apps/api:v1@sha256:abc123") == "v1"
    assert cli._image_ref_tag("registry.example.com/apps/api@sha256:abc123") is None
    assert cli._image_ref_tag("registry.example.com/apps/api") == "latest"


def test_cmd_scan_inventory_passes_pull_secret_auth_to_trivy(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "harbor.example.com/apps/api:v1",
                        "targets": [
                            {
                                "namespace": "apps",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                                "imagePullSecrets": ["harbor-creds"],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    docker_config = {"auths": {"harbor.example.com": {"auth": "dXNlcjpwYXNz"}}}
    secret = {
        "type": "kubernetes.io/dockerconfigjson",
        "data": {
            ".dockerconfigjson": base64.b64encode(json.dumps(docker_config).encode("utf-8")).decode("ascii")
        },
    }
    seen_auth_config: list[bool] = []
    monkeypatch.setattr(cli, "_fetch_kubernetes_secret", lambda namespace, name: secret)

    def fake_trivy(image: str, timeout: int = 120, docker_config_path: Path | None = None) -> dict:
        seen_auth_config.append(bool(docker_config_path and (docker_config_path / "config.json").exists()))
        return {"Results": []}

    monkeypatch.setattr(cli, "run_trivy_image_ref", fake_trivy)

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
        scan_types="image-sca",
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert seen_auth_config == [True]


def test_cmd_scan_inventory_prefers_admin_managed_parser_key(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "targets": [
                            {
                                "namespace": "apps",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ensure_calls: list[dict] = []

    def fake_ensure_source(*args, **kwargs):
        ensure_calls.append(kwargs)
        return args[2], "fresh-trivy-key"

    monkeypatch.setattr(cli, "ensure_source", fake_ensure_source)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: None)

    used_keys: list[str] = []
    monkeypatch.setattr(
        cli,
        "ingest_report",
        lambda _url, key, *args, **kwargs: used_keys.append(key) or {"ok": 1},
    )

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="stale-static-key",
        admin_token="admin-token",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=True,
        scan_types="image-sca",
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert used_keys == ["fresh-trivy-key"]
    # Never regenerate_key=True: _ensure_parser_ingest_key deliberately does
# NOT auto-regenerate on a cache miss, because rotating here invalidates the
# key every other scanner already holds. A real reset needs --reset-keys.
    assert ensure_calls
    assert all(call.get("regenerate_key") is False for call in ensure_calls)


def test_cmd_scan_inventory_summarizes_scanner_failures_without_error_spam(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "targets": [{"namespace": "apps", "kind": "Deployment", "name": "api"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: None)

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="inventory-key",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=True,
        scan_types="image-sca,image-sbom",
        verbose=False,
    )

    assert cli.cmd_scan_inventory(args) == 0

    captured = capsys.readouterr()
    assert "Inventory scan complete." in captured.out
    assert "scannerFailures=2" in captured.out
    assert "ERROR: Trivy image scan failed" not in captured.err
    assert "ERROR: Trivy CycloneDX image scan failed" not in captured.err


def test_ingest_retry_suppresses_transient_attempt_logs(monkeypatch, capsys) -> None:
    attempts = {"count": 0}

    def _flaky_ingest(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise cli.VATClientError("Ingest failed: [Errno 111] Connection refused")
        return {"ok": 1}

    monkeypatch.setattr(cli, "ingest_report", _flaky_ingest)
    monkeypatch.setattr(time, "sleep", lambda *_args, **_kwargs: None)

    result = cli._ingest_json_report_with_retry(
        vat_url="https://vat",
        key="k",
        report={"Results": []},
        asset_name="asset",
        tag=None,
        image_digest=None,
        label="trivy",
    )

    assert result == {"ok": 1}
    assert "ingest attempt" not in capsys.readouterr().err


def test_cmd_scan_k8s_inventory_prefers_admin_managed_parser_key(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "apps",
                        "kind": "Deployment",
                        "name": "api",
                        "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ensure_calls: list[dict] = []

    def fake_ensure_source(*args, **kwargs):
        ensure_calls.append(kwargs)
        return args[2], "fresh-trivy-key"

    monkeypatch.setattr(cli, "ensure_source", fake_ensure_source)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "run_trivy_fs", lambda *args, **kwargs: {"Results": []})

    used_keys: list[str] = []
    monkeypatch.setattr(
        cli,
        "ingest_report",
        lambda _url, key, *args, **kwargs: used_keys.append(key) or {"ok": 1},
    )

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="stale-static-key",
        admin_token="admin-token",
        no_snippets=False,
        reset_keys=False,
        cluster_name="k3s-remote",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=True,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    assert used_keys == ["fresh-trivy-key"]
    # Never regenerate_key=True: _ensure_parser_ingest_key deliberately does
# NOT auto-regenerate on a cache miss, because rotating here invalidates the
# key every other scanner already holds. A real reset needs --reset-keys.
    assert ensure_calls
    assert all(call.get("regenerate_key") is False for call in ensure_calls)


def test_cmd_scan_inventory_skips_unchanged_items_with_state(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    state_path = tmp_path / "state.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc123",
                        "targets": [
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            }
                        ],
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
                "images": {
                    "sha256:abc123": {
                        "signature": "sha256:abc123|default/Deployment/api/api|scanTypes=image-sca,image-sbom"
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    scan_calls = []
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: scan_calls.append(args) or {"Results": []})

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

    assert cli.cmd_scan_inventory(args) == 0
    assert scan_calls == []


def test_cmd_scan_inventory_seeds_last_full_scan_after_complete_pass(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    state_path = tmp_path / "state.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc123",
                        "targets": [
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *args, **kwargs: {"Results": []})
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *args, **kwargs: {"components": []})
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

    assert cli.cmd_scan_inventory(args) == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state.get("lastFullScanAt")


def test_cmd_scan_inventory_force_full_rescan_ignores_state(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    state_path = tmp_path / "state.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc123",
                        "targets": [
                            {
                                "namespace": "default",
                                "kind": "Deployment",
                                "name": "api",
                                "containerName": "api",
                            }
                        ],
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
                "images": {
                    "sha256:abc123": {
                        "signature": "sha256:abc123|default/Deployment/api/api"
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    scan_calls = []
    monkeypatch.setattr(
        cli,
        "run_trivy_image_ref",
        lambda image, timeout=120, **kwargs: scan_calls.append(image) or {"Results": [{"Target": image}]},
    )
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
        force_full_rescan=True,
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert scan_calls == ["registry.example.com/api:v1"]
