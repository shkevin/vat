from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from vat_scanner import config, snippet_enrichment, snippets, vat_client


class _Response:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_config_env_expand_and_find(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VAT_URL", "https://vat.test")
    monkeypatch.setenv("TOKEN", "abc")
    assert config._expand_env("${TOKEN}") == "abc"
    assert config._expand_env_in_dict({"x": ["$TOKEN"]}) == {"x": ["abc"]}

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    cfg = repo / "vat-scanner.yaml"
    cfg.write_text("vat_url: ${VAT_URL}\n", encoding="utf-8")
    found = config.find_config_file(repo, None)
    assert found == cfg
    loaded = config.load_config_file(cfg)
    assert loaded["vat_url"] == "https://vat.test"


def test_config_ignore_and_scanner_config(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".vatignore").write_text("#c\nnode_modules/**\n", encoding="utf-8")
    (repo / ".gitignore").write_text("artifacts/\n!keep-me/\n", encoding="utf-8")
    assert config.load_ignore_file(repo) == ["node_modules/**"]
    assert config.load_ignore_file(repo, include_gitignore=True) == [
        "node_modules/**",
        "artifacts/",
    ]

    cfg_path = repo / "vat-scanner.yaml"
    cfg_path.write_text(
        json.dumps(
            {
                "asset": "my-asset",
                "scan_types": ["code", "dependencies"],
                "exclude": ["dist/**"],
                "gating": {"mode": "pr", "fail_on": "high"},
                "scan_timeout_ms": 12345,
                "disable_artifact_scanning": True,
            }
        ),
        encoding="utf-8",
    )
    # safe_load can parse JSON as YAML
    sc = config.ScannerConfig.from_file(cfg_path, repo)
    assert sc.asset == "my-asset"
    assert "code" in sc.scan_types
    assert sc.gating_mode == "pr"
    assert sc.fail_on == "high"
    assert sc.disable_artifact_scanning is True

    merged = sc.merge_cli(asset="override", verbose=True, asset_mode="bad-value")
    assert merged.asset == "override"
    assert merged.verbose is True
    assert merged.asset_mode == "multi"


def test_strip_snippets_recursive() -> None:
    report = {"a": 1, "Code": "x", "nested": [{"Secret": "s", "keep": True}]}
    out = snippets.strip_snippets(report)
    assert "Code" not in out
    assert "Secret" not in out["nested"][0]
    assert out["nested"][0]["keep"] is True


def test_snippet_enrichment_helpers_and_report(tmp_path: Path) -> None:
    target = tmp_path / "src" / "a.py"
    target.parent.mkdir(parents=True)
    target.write_text("line1\npassword=SECRET\nline3\n", encoding="utf-8")

    assert snippet_enrichment._read_line_at(tmp_path, "src/a.py", 2) == "password=SECRET"
    assert snippet_enrichment._read_line_at(tmp_path, "/abs/path", 2) is None
    assert snippet_enrichment._mask_secret_in_line("password=SECRET", "SECRET").endswith("***REDACTED***")

    finding = {"File": "src/a.py", "StartLine": 2, "Secret": "SECRET"}
    snippet_enrichment._enrich_finding_with_file_line(finding, tmp_path, {})
    assert "Content" in finding

    trivy_result = {
        "Target": "src/a.py",
        "Secrets": [{"Match": "SECRET", "Code": {"Lines": [{"Number": 2, "Content": ""}]}}],
    }
    snippet_enrichment._enrich_result_with_secrets(trivy_result, tmp_path, {})
    lines = trivy_result["Secrets"][0]["Code"]["Lines"][0]
    assert lines["Content"].endswith("***REDACTED***")

    semgrep_row = {"path": "src/a.py", "start": {"line": 1}, "extra": {}}
    snippet_enrichment._enrich_result_with_path_start(semgrep_row, tmp_path, {})
    assert semgrep_row["extra"]["lines"] == "line1"

    report = {"Results": [trivy_result, semgrep_row]}
    snippet_enrichment._enrich_report(report, tmp_path)
    snippet_enrichment.enrich_reports({"x": report}, tmp_path)


def test_vat_client_cache_and_source_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(vat_client, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(vat_client, "CACHE_FILE", tmp_path / "scanner-keys.json")
    assert vat_client.source_id_for_parser("trivy") == "trivy"
    assert vat_client.get_cached_key("missing") is None
    vat_client.cache_key("trivy", "k1")
    assert vat_client.get_cached_key("trivy") == "k1"


def test_vat_client_http_calls_and_errors(monkeypatch) -> None:
    def _ok_urlopen(req, timeout=0):
        if req.full_url.endswith("/ensure"):
            return _Response({"sourceId": "trivy", "key": "k"})
        return _Response({"created": 1})

    monkeypatch.setattr(vat_client.urllib.request, "urlopen", _ok_urlopen)
    source_id, key = vat_client.ensure_source("https://vat.test", "adm", "trivy")
    assert source_id == "trivy"
    assert key == "k"
    assert vat_client.ingest_report("https://vat.test", "k", {"Results": []}) == {"created": 1}
    assert vat_client.ingest_openscap_report("https://vat.test", "k", "<xml/>") == {"created": 1}
    assert vat_client.ingest_openscap_oval_report("https://vat.test", "k", b"<xml/>") == {"created": 1}

    body_fp = io.BytesIO(b'{"error":"bad"}')
    http_err = urllib.error.HTTPError("u", 400, "bad", hdrs=None, fp=body_fp)

    def _http_error(req, timeout=0):
        raise http_err

    monkeypatch.setattr(vat_client.urllib.request, "urlopen", _http_error)
    with pytest.raises(vat_client.VATClientError):
        vat_client.ensure_source("https://vat.test", "adm", "trivy")
    with pytest.raises(vat_client.VATClientError):
        vat_client.ingest_report("https://vat.test", "k", {"x": 1})
