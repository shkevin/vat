"""Unit tests for the event-driven scan-queue consumer (Phase 3)."""

from __future__ import annotations

import urllib.error

import pytest

from vat_scanner import cli
from vat_scanner.scanrequests import K8sConflict, K8sError, ScanRequestClient


def test_pull_target_resolves_digest_and_tag() -> None:
    spec = {"imageRef": "harbor.io/acme/app:1.4", "digest": "sha256:" + "a" * 64, "tags": ["1.4"]}
    pull_ref, asset, tag, digest = cli._scan_request_pull_target(spec)
    assert pull_ref == "harbor.io/acme/app@sha256:" + "a" * 64  # pull by digest
    assert asset == "harbor.io/acme/app:1.4"  # ingest under tag ref
    assert tag == "1.4"
    assert digest == "sha256:" + "a" * 64


def test_pull_target_falls_back_to_imageref_without_digest() -> None:
    pull_ref, asset, tag, digest = cli._scan_request_pull_target({"imageRef": "ghcr.io/x/y:latest"})
    assert pull_ref == "ghcr.io/x/y:latest"
    assert tag == "latest"
    assert digest is None


def test_scan_types_filtered_and_defaulted() -> None:
    assert cli._scan_request_scan_types({"scanTypes": ["image-sca", "bogus"]}) == ["image-sca"]
    assert cli._scan_request_scan_types({}) == list(cli._QUEUE_SCAN_TYPES)


def test_backoff_gates_failed_requests() -> None:
    # No prior attempts -> always ready.
    assert cli._backoff_ready({"attempts": 0}, now=1_000_000.0)
    # 2 attempts, finished "now": base*2^1 = 60s window, not yet ready.
    status = {"attempts": 2, "finishedAt": "2026-01-01T00:00:00Z"}
    base_ts = 1_767_225_600.0  # 2026-01-01T00:00:00Z
    assert not cli._backoff_ready(status, now=base_ts + 10)
    assert cli._backoff_ready(status, now=base_ts + 61)


class _FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code: int):
        super().__init__("http://x", code, "err", {}, None)


def test_client_maps_409_to_conflict(monkeypatch) -> None:
    client = ScanRequestClient(namespace="vat-operator")
    client._token = "t"  # pretend in-cluster

    def boom(*_a, **_k):
        raise _FakeHTTPError(409)

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(K8sConflict):
        client.update_status({"metadata": {"name": "r1", "resourceVersion": "5"}})


def test_client_maps_other_errors(monkeypatch) -> None:
    client = ScanRequestClient(namespace="vat-operator")
    client._token = "t"
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(_FakeHTTPError(500)))
    with pytest.raises(K8sError):
        client.list()
