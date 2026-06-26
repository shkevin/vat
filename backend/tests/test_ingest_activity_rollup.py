from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.api import ingest as ingest_api
from app.schemas.vat import VatFindingSchema, VatFindingType, VatSeverity


class _Parser:
    def __init__(self, payloads):
        self._payloads = payloads

    def parse(self, _raw):
        return self._payloads


class _Policy:
    sbom_tag = None
    force_override = False

    def apply_to_payload(self, payload):
        return payload

    async def normalize_existing_source_asset_tags(self, db, source_name: str, asset_id: str):
        return 0


class _Resolution:
    def __init__(self, asset_id: str, asset_kind: str = "image"):
        self.raw_asset_id = asset_id
        self.asset_id = asset_id
        self.reason = "explicit_asset"
        self.confidence = "high"
        self.asset_kind = asset_kind

    def to_api_dict(self):
        return {"assetId": self.asset_id}


def _payload(cve: str, image: str = "asset-a") -> VatFindingSchema:
    return VatFindingSchema(
        cve_id=cve,
        severity=VatSeverity.HIGH,
        description="rollup-test",
        finding_type=VatFindingType.SCA,
        title="rollup",
        image=image,
        component="openssl 3.0.0",
    )


@pytest.mark.asyncio
async def test_ingest_rollup_emits_timeout_and_final_windows(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    payloads = [_payload("CVE-2026-1000"), _payload("CVE-2026-1001")]
    emit_spy = AsyncMock(return_value="evt")
    finding_spy = AsyncMock(
        side_effect=[
            (SimpleNamespace(id="f-1"), True),
            (SimpleNamespace(id="f-2"), False),
        ]
    )
    mono_values = iter([0.0, 0.1, 1.5, 1.6, 1.7])

    monkeypatch.setattr(ingest_api, "get_parser", lambda _parser_id: _Parser(payloads))
    monkeypatch.setattr(ingest_api, "emit_audit_event", emit_spy)
    monkeypatch.setattr(
        ingest_api,
        "get_settings",
        lambda: SimpleNamespace(
            ingest_rollup_window_seconds=1,
            ingest_rollup_idle_timeout_seconds=30,
            ingest_rollup_sample_size=5,
        ),
    )
    monkeypatch.setattr(ingest_api, "IngestTagPolicy", SimpleNamespace(from_headers=lambda **_: _Policy()))
    monkeypatch.setattr(ingest_api, "enrich_payload_for_correlation", lambda p, **_: p)
    monkeypatch.setattr(
        ingest_api,
        "resolve_asset_for_payload",
        lambda p, **_: (p, _Resolution((p.image or p.component))),
    )
    monkeypatch.setattr(ingest_api, "resolve_canonical_asset_id", AsyncMock(return_value=None))
    monkeypatch.setattr(ingest_api, "_ensure_asset_record", AsyncMock(return_value=False))
    monkeypatch.setattr(ingest_api, "ingest_finding", finding_spy)
    monkeypatch.setattr(ingest_api, "extract_sbom_from_report", lambda *_: None)
    monkeypatch.setattr(ingest_api, "monotonic", lambda: next(mono_values))

    result = await ingest_api._ingest_from_parser(
        db,
        raw={"runs": []},
        parser_id="sarif",
        source="vat-local-trivy",
        source_config=None,
        trace_id="trace-rollup",
        actor_id="source-a",
    )

    assert result["created"] == 1
    assert result["merged"] == 1

    event_types = [call.kwargs.get("event_type") for call in emit_spy.await_args_list]
    assert "asset.mapping.resolved" not in event_types
    assert "dedup.replay.new" not in event_types
    assert "dedup.replay.merged" not in event_types

    rollup_calls = [
        call.kwargs for call in emit_spy.await_args_list if call.kwargs.get("event_type") == "ingest.rollup.window"
    ]
    assert len(rollup_calls) == 2
    assert rollup_calls[0]["data"]["flushReason"] == "timeout"
    assert rollup_calls[1]["data"]["flushReason"] == "ingest_complete"
    assert rollup_calls[0]["data"]["sampledMappings"]
    assert rollup_calls[0]["data"]["sampledDedup"]


@pytest.mark.asyncio
async def test_ingest_rollup_disabled_keeps_per_finding_events(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    payloads = [_payload("CVE-2026-2000")]
    emit_spy = AsyncMock(return_value="evt")

    monkeypatch.setattr(ingest_api, "get_parser", lambda _parser_id: _Parser(payloads))
    monkeypatch.setattr(ingest_api, "emit_audit_event", emit_spy)
    monkeypatch.setattr(
        ingest_api,
        "get_settings",
        lambda: SimpleNamespace(
            ingest_rollup_window_seconds=0,
            ingest_rollup_idle_timeout_seconds=0,
            ingest_rollup_sample_size=5,
        ),
    )
    monkeypatch.setattr(ingest_api, "IngestTagPolicy", SimpleNamespace(from_headers=lambda **_: _Policy()))
    monkeypatch.setattr(ingest_api, "enrich_payload_for_correlation", lambda p, **_: p)
    monkeypatch.setattr(
        ingest_api,
        "resolve_asset_for_payload",
        lambda p, **_: (p, _Resolution((p.image or p.component))),
    )
    monkeypatch.setattr(ingest_api, "resolve_canonical_asset_id", AsyncMock(return_value=None))
    monkeypatch.setattr(ingest_api, "_ensure_asset_record", AsyncMock(return_value=False))
    monkeypatch.setattr(
        ingest_api,
        "ingest_finding",
        AsyncMock(return_value=(SimpleNamespace(id="f-1"), True)),
    )
    monkeypatch.setattr(ingest_api, "extract_sbom_from_report", lambda *_: None)

    await ingest_api._ingest_from_parser(
        db,
        raw={"runs": []},
        parser_id="sarif",
        source="vat-local-trivy",
        source_config=None,
        trace_id="trace-raw-events",
        actor_id="source-a",
    )

    event_types = [call.kwargs.get("event_type") for call in emit_spy.await_args_list]
    assert "asset.mapping.resolved" in event_types
    assert "dedup.replay.new" in event_types
    assert "ingest.rollup.window" not in event_types


@pytest.mark.asyncio
async def test_ingest_ensures_asset_record_for_merged_findings(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    asset_id = "ghcr.io/acme/coredns"
    payloads = [_payload("AVD-KSV-0001", image=asset_id)]
    ensure_asset = AsyncMock(return_value=True)

    monkeypatch.setattr(ingest_api, "get_parser", lambda _parser_id: _Parser(payloads))
    monkeypatch.setattr(ingest_api, "emit_audit_event", AsyncMock(return_value="evt"))
    monkeypatch.setattr(
        ingest_api,
        "get_settings",
        lambda: SimpleNamespace(
            ingest_rollup_window_seconds=0,
            ingest_rollup_idle_timeout_seconds=0,
            ingest_rollup_sample_size=5,
        ),
    )
    monkeypatch.setattr(ingest_api, "IngestTagPolicy", SimpleNamespace(from_headers=lambda **_: _Policy()))
    monkeypatch.setattr(ingest_api, "enrich_payload_for_correlation", lambda p, **_: p)
    monkeypatch.setattr(
        ingest_api,
        "resolve_asset_for_payload",
        lambda p, **_: (p, _Resolution((p.image or p.component), "container")),
    )
    monkeypatch.setattr(ingest_api, "resolve_canonical_asset_id", AsyncMock(return_value=None))
    monkeypatch.setattr(
        ingest_api,
        "ingest_finding",
        AsyncMock(return_value=(SimpleNamespace(id="f-merged"), False)),
    )
    monkeypatch.setattr(ingest_api, "extract_sbom_from_report", lambda *_: None)
    monkeypatch.setattr(ingest_api, "_ensure_asset_record", ensure_asset)

    result = await ingest_api._ingest_from_parser(
        db,
        raw={"Results": []},
        parser_id="trivy",
        source="trivy",
        source_config={"asset_type": "package"},
        trace_id="trace-merged-asset",
        actor_id="source-a",
    )

    assert result["merged"] == 1
    ensure_asset.assert_awaited_once_with(db, asset_id, "trivy", "container")


@pytest.mark.asyncio
async def test_ingest_does_not_create_asset_record_for_kubernetes_inventory_paths(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    asset_id = "k8s/k3s-remote/monitoring/service/alloy"
    payloads = [_payload("AVD-KSV-0002", image=asset_id)]
    ensure_asset = AsyncMock(return_value=True)

    monkeypatch.setattr(ingest_api, "get_parser", lambda _parser_id: _Parser(payloads))
    monkeypatch.setattr(ingest_api, "emit_audit_event", AsyncMock(return_value="evt"))
    monkeypatch.setattr(
        ingest_api,
        "get_settings",
        lambda: SimpleNamespace(
            ingest_rollup_window_seconds=0,
            ingest_rollup_idle_timeout_seconds=0,
            ingest_rollup_sample_size=5,
        ),
    )
    monkeypatch.setattr(ingest_api, "IngestTagPolicy", SimpleNamespace(from_headers=lambda **_: _Policy()))
    monkeypatch.setattr(ingest_api, "enrich_payload_for_correlation", lambda p, **_: p)
    monkeypatch.setattr(
        ingest_api,
        "resolve_asset_for_payload",
        lambda p, **_: (p, _Resolution((p.image or p.component), "package_scope")),
    )
    monkeypatch.setattr(ingest_api, "resolve_canonical_asset_id", AsyncMock(return_value=None))
    monkeypatch.setattr(
        ingest_api,
        "ingest_finding",
        AsyncMock(return_value=(SimpleNamespace(id="f-k8s"), False)),
    )
    monkeypatch.setattr(ingest_api, "extract_sbom_from_report", lambda *_: None)
    monkeypatch.setattr(ingest_api, "_ensure_asset_record", ensure_asset)

    result = await ingest_api._ingest_from_parser(
        db,
        raw={"Results": []},
        parser_id="trivy",
        source="trivy",
        source_config={"asset_type": "package"},
        trace_id="trace-k8s-hidden-asset",
        actor_id="source-a",
    )

    assert result["merged"] == 1
    ensure_asset.assert_not_awaited()


@pytest.mark.asyncio
async def test_zero_finding_kubernetes_inventory_stub_does_not_create_asset_record(monkeypatch):
    db = SimpleNamespace(commit=AsyncMock())
    asset_id = "k8s/k3s-remote/cluster/clusterrole/alloy"
    ensure_asset = AsyncMock(return_value=True)

    monkeypatch.setattr(ingest_api, "get_parser", lambda _parser_id: _Parser([]))
    monkeypatch.setattr(ingest_api, "emit_audit_event", AsyncMock(return_value="evt"))
    monkeypatch.setattr(
        ingest_api,
        "get_settings",
        lambda: SimpleNamespace(
            ingest_rollup_window_seconds=0,
            ingest_rollup_idle_timeout_seconds=0,
            ingest_rollup_sample_size=5,
        ),
    )
    monkeypatch.setattr(ingest_api, "IngestTagPolicy", SimpleNamespace(from_headers=lambda **_: _Policy()))
    monkeypatch.setattr(
        ingest_api,
        "resolve_ingest_stub_asset_identity",
        AsyncMock(return_value=(asset_id, "package")),
    )
    monkeypatch.setattr(ingest_api, "_ensure_asset_record", ensure_asset)

    result = await ingest_api._ingest_from_parser(
        db,
        raw={"Results": []},
        parser_id="trivy",
        source="trivy",
        source_config={"asset_type": "package"},
        trace_id="trace-k8s-empty-stub",
        actor_id="source-a",
        asset_override=asset_id,
    )

    assert result["created"] == 0
    assert result["merged"] == 0
    ensure_asset.assert_not_awaited()
