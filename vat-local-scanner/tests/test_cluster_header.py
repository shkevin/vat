"""Multi-cluster: every ingest report stamps X-VAT-Cluster from the deployment env."""

from __future__ import annotations

from vat_scanner.vat_client import _ingest_headers


def test_cluster_header_from_cluster_name(monkeypatch):
    monkeypatch.setenv("VAT_CLUSTER_NAME", "prod-east")
    monkeypatch.delenv("CLUSTER_NAME", raising=False)
    h = _ingest_headers("k", asset="registry/app:v1", tag="v1")
    assert h["X-VAT-Cluster"] == "prod-east"


def test_cluster_header_falls_back_to_cluster_name_env(monkeypatch):
    monkeypatch.delenv("VAT_CLUSTER_NAME", raising=False)
    monkeypatch.setenv("CLUSTER_NAME", "kind-2")
    h = _ingest_headers("k")
    assert h["X-VAT-Cluster"] == "kind-2"


def test_no_cluster_header_when_unset(monkeypatch):
    monkeypatch.delenv("VAT_CLUSTER_NAME", raising=False)
    monkeypatch.delenv("CLUSTER_NAME", raising=False)
    h = _ingest_headers("k")
    assert "X-VAT-Cluster" not in h
