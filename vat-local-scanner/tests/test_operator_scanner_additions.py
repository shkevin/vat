"""Operator inventory scan additions: Grype 2nd-opinion SCA + Gitleaks on k8s config."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vat_scanner import cli


def test_parse_inventory_scan_types_recognizes_grype(monkeypatch) -> None:
    monkeypatch.delenv("VAT_INVENTORY_SCAN_TYPES", raising=False)
    assert cli._parse_inventory_scan_types("image-sca,image-grype,image-sbom") == [
        "image-sca",
        "image-grype",
        "image-sbom",
    ]
    assert cli._parse_inventory_scan_types("grype") == ["image-grype"]  # alias
    assert "image-grype" in cli._parse_inventory_scan_types("all")
    # Bare default stays Trivy-only; the operator opts into grype via env/flag.
    assert cli._parse_inventory_scan_types("") == ["image-sca", "image-sbom"]


def test_cmd_scan_inventory_ingests_grype_second_opinion(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc",
                        "targets": [
                            {"namespace": "apps", "kind": "Deployment", "name": "api", "containerName": "api"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ingested: list[dict] = []
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *a, **k: {"Results": [{"Target": "x"}]})
    monkeypatch.setattr(
        cli, "run_grype_image_ref", lambda *a, **k: {"matches": [{"vulnerability": {"id": "CVE-1"}}]}
    )
    monkeypatch.setattr(cli, "ingest_report", lambda url, key, report, **kwargs: ingested.append(report) or {"ok": 1})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="c",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
        scan_types="image-sca,image-grype",
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert any("Results" in r for r in ingested), "trivy report ingested"
    assert any("matches" in r for r in ingested), "grype report ingested"


def test_grype_reuses_sbom_without_second_image_pull(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "images.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "targets": [
                            {"namespace": "apps", "kind": "Deployment", "name": "api", "containerName": "api"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ingested: list[dict] = []
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *a, **k: {"Results": []})
    monkeypatch.setattr(cli, "run_trivy_image_ref_cyclonedx", lambda *a, **k: {"components": [{"name": "pkg"}]})
    monkeypatch.setattr(cli, "run_grype_sbom", lambda *a, **k: {"matches": [{"vulnerability": {"id": "CVE-9"}}]})

    def _no_pull(*a, **k):
        raise AssertionError("grype must scan the CycloneDX SBOM, not re-pull the image")

    monkeypatch.setattr(cli, "run_grype_image_ref", _no_pull)
    monkeypatch.setattr(cli, "ingest_report", lambda url, key, report, **kwargs: ingested.append(report) or {"ok": 1})

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="c",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
        scan_types="image-sca,image-grype,image-sbom",
    )

    assert cli.cmd_scan_inventory(args) == 0
    assert any("matches" in r for r in ingested), "grype-from-sbom report ingested"


def test_grype_failure_stays_incremental(monkeypatch, tmp_path: Path) -> None:
    """A failing grype (best-effort second opinion) must not block the per-image
    checkpoint — the image still gets skipped on the next pass."""
    inventory_path = tmp_path / "images.json"
    state_path = tmp_path / "state.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "image": "registry.example.com/api:v1",
                        "imageDigest": "sha256:abc",
                        "targets": [
                            {"namespace": "apps", "kind": "Deployment", "name": "api", "containerName": "api"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *a, **k: {"Results": []})
    monkeypatch.setattr(cli, "run_grype_sbom", lambda *a, **k: None)  # grype fails
    monkeypatch.setattr(cli, "run_grype_image_ref", lambda *a, **k: None)  # fallback also fails
    monkeypatch.setattr(cli, "ingest_report", lambda *a, **k: {"ok": 1})

    def _args() -> argparse.Namespace:
        return argparse.Namespace(
            inventory=inventory_path,
            dry_run=False,
            fail_on_error=False,
            vat_url="https://vat",
            api_key="k",
            admin_token="",
            no_snippets=False,
            reset_keys=False,
            cluster_name="c",
            state_file=state_path,
            full_rescan_interval_seconds=86400,
            force_full_rescan=False,
            scan_types="image-sca,image-grype",
        )

    assert cli.cmd_scan_inventory(_args()) == 0  # first pass checkpoints despite grype miss
    scanned: list[int] = []
    monkeypatch.setattr(cli, "run_trivy_image_ref", lambda *a, **k: scanned.append(1) or {"Results": []})
    assert cli.cmd_scan_inventory(_args()) == 0
    assert scanned == [], "unchanged image must be skipped on the second pass"


def test_cmd_scan_k8s_inventory_ingests_gitleaks_under_namespace_asset(monkeypatch, tmp_path: Path) -> None:
    inventory_path = tmp_path / "kubernetes.json"
    inventory_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "namespace": "default",
                        "kind": "Deployment",
                        "name": "api",
                        "resourceVersion": "1",
                        "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ingested: list[tuple] = []
    monkeypatch.setattr(cli, "run_trivy_fs", lambda folder, **k: {"Results": []})
    monkeypatch.setattr(cli, "run_gitleaks", lambda *a, **k: [{"RuleID": "generic-api-key", "Secret": "x"}])
    monkeypatch.setattr(
        cli, "ingest_report", lambda url, key, report, **kwargs: ingested.append((report, kwargs.get("asset"))) or {"ok": 1}
    )

    args = argparse.Namespace(
        inventory=inventory_path,
        dry_run=False,
        fail_on_error=False,
        vat_url="https://vat",
        api_key="k",
        admin_token="",
        no_snippets=False,
        reset_keys=False,
        cluster_name="c",
        state_file=None,
        full_rescan_interval_seconds=86400,
        force_full_rescan=False,
    )

    assert cli.cmd_scan_k8s_inventory(args) == 0
    # Gitleaks findings ingested, and everything lands on the namespace asset.
    assert any(isinstance(r, dict) and "findings" in r for r, _ in ingested), "gitleaks report ingested"
    assert {asset for _, asset in ingested} == {"k8s/c/default"}
