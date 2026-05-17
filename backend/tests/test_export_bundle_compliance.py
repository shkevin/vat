"""Compliance export bundle: manifest, CSV, waivers, PDF, audit embed."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.finding import Finding, FindingType, Severity, Status
from app.services.export_service import (
    ExportBundleOptions,
    _build_waiver_records,
    build_export_bundle,
)


def _waiver_finding(finding_id: str = "wf1", image: str = "api:latest") -> Finding:
    ts = datetime(2025, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
    return Finding(
        id=finding_id,
        finding_type=FindingType.SCA,
        fingerprint_id="fp_waiver_1",
        cve_id="CVE-2024-99999",
        severity=Severity.High,
        status=Status.RiskAccepted,
        title="Test waiver row",
        component="openssl 3",
        image=image,
        control_ref="CC6.6",
        attestation={
            "approver": "Sam Reviewer",
            "approverTitle": "CISO",
            "approvedAt": "2025-01-15T10:00:00Z",
            "waiverRef": "WAV-TEST-001",
            "expiresAt": "2026-12-31",
        },
        sources=[],
        external_links=[],
        tracker_comment=False,
        regression_count=0,
        audit=[],
        archived=False,
        created_at=ts,
        updated_at=ts,
        first_detected_at=ts,
    )


@pytest.mark.asyncio
async def test_build_export_bundle_compliance_artifacts_and_manifest_hashes(monkeypatch):
    async def mock_list_findings(*_a, **_k):
        return [_waiver_finding()]

    monkeypatch.setattr(
        "app.services.export_service.list_findings",
        mock_list_findings,
    )
    monkeypatch.setattr(
        "app.services.export_service.enrich_findings_with_source_group_severity",
        AsyncMock(side_effect=lambda _db, rows: rows),
    )
    monkeypatch.setattr(
        "app.services.export_service.get_assets_with_findings",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_sbom_packages",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_openscap_scan_results",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.load_audit_events_for_export",
        AsyncMock(
            return_value=[
                {"event_id": "evt-1", "event_type": "test.event", "data": {}},
            ]
        ),
    )

    db = MagicMock()
    ctx = SimpleNamespace(tenant_id="tenant-a", cross_tenant=False)
    data = await build_export_bundle(
        db,
        ctx=ctx,
        options=ExportBundleOptions(include_audit_events=True),
    )
    assert data.startswith(b"PK")

    zf = zipfile.ZipFile(io.BytesIO(data), "r")
    names = zf.namelist()
    prefix = [n for n in names if n.startswith("vat-export-")][0].split("/")[0]

    expected = {
        f"{prefix}/evidence-manifest.json",
        f"{prefix}/assets-findings.json",
        f"{prefix}/findings.csv",
        f"{prefix}/waivers.json",
        f"{prefix}/waivers.csv",
        f"{prefix}/executive-summary-yearly.html",
        f"{prefix}/audit-events.json",
        f"{prefix}/sbom/sbom-cyclonedx.json",
        f"{prefix}/auditor-workbook.xlsx",
        f"{prefix}/stig/README-STIG-Viewer.txt",
    }
    for path in expected:
        assert path in names, f"missing {path}"
    assert f"{prefix}/compliance-summary.pdf" not in names

    manifest = json.loads(zf.read(f"{prefix}/evidence-manifest.json").decode())
    assert manifest["schemaVersion"] == "evidence-v2"
    assert manifest["packageType"] == "vat-compliance-bundle"
    assert manifest["tenantId"] == "tenant-a"
    assert "vatBackendVersion" in manifest
    assert manifest["exportOptions"]["include_audit_events"] is True

    by_path = {e["path"]: e for e in manifest["files"]}
    for rel, zpath in [
        ("findings.csv", f"{prefix}/findings.csv"),
        ("audit-events.json", f"{prefix}/audit-events.json"),
    ]:
        raw = zf.read(zpath)
        assert by_path[rel]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert by_path[rel]["sizeBytes"] == len(raw)

    waivers = json.loads(zf.read(f"{prefix}/waivers.json").decode())
    assert len(waivers) == 1
    assert waivers[0]["waiverRef"] == "WAV-TEST-001"
    assert waivers[0]["approver"] == "Sam Reviewer"

    wcsv = zf.read(f"{prefix}/waivers.csv").decode()
    r = list(csv.DictReader(io.StringIO(wcsv)))
    assert len(r) == 1
    assert r[0]["waiverRef"] == "WAV-TEST-001"


@pytest.mark.asyncio
async def test_build_export_bundle_skips_audit_when_disabled(monkeypatch):
    async def mock_list_findings(*_a, **_k):
        return []

    monkeypatch.setattr(
        "app.services.export_service.list_findings",
        mock_list_findings,
    )
    monkeypatch.setattr(
        "app.services.export_service.enrich_findings_with_source_group_severity",
        AsyncMock(side_effect=lambda _db, rows: rows),
    )
    monkeypatch.setattr(
        "app.services.export_service.get_assets_with_findings",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_sbom_packages",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_openscap_scan_results",
        AsyncMock(return_value=[]),
    )
    spy = AsyncMock(return_value=[])
    monkeypatch.setattr(
        "app.services.export_service.load_audit_events_for_export",
        spy,
    )

    db = MagicMock()
    ctx = SimpleNamespace(tenant_id="tenant-a", cross_tenant=False)
    await build_export_bundle(
        db,
        ctx=ctx,
        options=ExportBundleOptions(include_audit_events=False),
    )
    spy.assert_not_called()


@pytest.mark.asyncio
async def test_build_export_bundle_scopes_to_selected_assets(monkeypatch):
    async def mock_list_findings(*_a, **_k):
        return [
            _waiver_finding("wf1", "asset-a"),
            _waiver_finding("wf2", "asset-b"),
        ]

    monkeypatch.setattr(
        "app.services.export_service.list_findings",
        mock_list_findings,
    )
    monkeypatch.setattr(
        "app.services.export_service.enrich_findings_with_source_group_severity",
        AsyncMock(side_effect=lambda _db, rows: rows),
    )
    monkeypatch.setattr(
        "app.services.export_service.get_assets_with_findings",
        AsyncMock(
            return_value=[
                {"id": "asset-a", "name": "asset-a", "findingIds": ["wf1"], "findings": []},
                {"id": "asset-b", "name": "asset-b", "findingIds": ["wf2"], "findings": []},
            ]
        ),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_sbom_packages",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.list_openscap_scan_results",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "app.services.export_service.load_audit_events_for_export",
        AsyncMock(return_value=[]),
    )

    db = MagicMock()
    ctx = SimpleNamespace(tenant_id="tenant-a", cross_tenant=False)
    data = await build_export_bundle(
        db,
        ctx=ctx,
        options=ExportBundleOptions(
            apply_asset_filter=True,
            asset_ids=["asset-a"],
            include_audit_events=False,
        ),
    )
    zf = zipfile.ZipFile(io.BytesIO(data), "r")
    names = zf.namelist()
    prefix = [n for n in names if n.startswith("vat-export-")][0].split("/")[0]
    payload = json.loads(zf.read(f"{prefix}/assets-findings.json").decode())
    assert [f["id"] for f in payload["findings"]] == ["wf1"]
    assert [a["id"] for a in payload["assets"]] == ["asset-a"]


def test_build_waiver_records_filters_status():
    rows = [
        {"id": "a", "status": "Open", "attestation": {}},
        {"id": "b", "status": "Risk Accepted", "attestation": {"waiverRef": "W"}},
    ]
    rec = _build_waiver_records(rows)
    assert len(rec) == 1
    assert rec[0]["findingId"] == "b"
