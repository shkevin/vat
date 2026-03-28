from __future__ import annotations

import argparse
import json
import sys
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
    args.admin_token = "adm"
    monkeypatch.setattr(cli, "ensure_source", lambda *args, **kwargs: ("trivy", "k"))
    monkeypatch.setattr(cli, "cache_key", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "get_cached_key", lambda *args, **kwargs: "k")
    monkeypatch.setattr(cli, "ingest_report", lambda *args, **kwargs: {"ok": 1})
    assert cli.cmd_scan_image(args) == 0
