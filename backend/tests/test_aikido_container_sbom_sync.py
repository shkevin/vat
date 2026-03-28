"""Aikido container SBOM sync: digest backfill from CycloneDX license export."""

import uuid
from types import SimpleNamespace

import pytest

from app.models.finding import Finding, FindingType, Severity, Status
from app.services.aikido_container_sbom_sync import (
    iter_cyclonedx_from_aikido_bulk_sbom,
    preferred_sbom_component_for_aikido_container,
    sync_aikido_container_sboms,
)


def test_preferred_sbom_component_docker_io_prefix():
    assert (
        preferred_sbom_component_for_aikido_container(
            "containers/images/foo", {}
        )
        == "docker.io/containers/images/foo"
    )
    assert (
        preferred_sbom_component_for_aikido_container(
            "kamiwaza/images/bar", {}
        )
        == "docker.io/kamiwaza/images/bar"
    )


def test_preferred_sbom_component_uses_explicit_image():
    assert (
        preferred_sbom_component_for_aikido_container(
            "containers/images/x",
            {"image": "registry.example/ns/app:1.0"},
        )
        == "registry.example/ns/app"
    )


@pytest.mark.asyncio
async def test_sync_backfills_aikido_finding_digest(db, monkeypatch):
    h = "c" * 64
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "name": "demo:1.0",
                "purl": f"pkg:oci/demo@sha256%3A{h}",
                "properties": [
                    {
                        "name": "aquasecurity:trivy:RepoDigest",
                        "value": f"demo@sha256:{h}",
                    },
                ],
            }
        },
        "components": [
            {
                "name": "openssl",
                "version": "3.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        ],
    }

    fp = f"fp-aikido-sbom-{uuid.uuid4().hex[:16]}"
    # Findings use full registry path (same as local scanner / ingest headers)
    img = "docker.io/containers/images/aikido-sbom-test-asset"
    f_row = Finding(
        id=f"f-{uuid.uuid4().hex[:10]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp,
        cve_id="CVE-2024-99999",
        severity=Severity.High,
        status=Status.Open,
        source="Aikido",
        image=img,
        tag="1.0",
        image_digest=None,
    )
    db.add(f_row)
    await db.commit()

    async def fake_fetch(cid, credentials=None):
        assert str(cid) == "42"
        return cdx

    monkeypatch.setattr(
        "app.services.aikido_container_sbom_sync.fetch_aikido_container_licenses_export",
        fake_fetch,
    )

    stats = await sync_aikido_container_sboms(
        db,
        {"client_id": "t", "client_secret": "s", "region": "eu"},
        [{"id": 42, "name": "containers/images/aikido-sbom-test-asset:1.0"}],
        source_id="src-test",
    )

    assert stats["fetch_ok"] >= 1
    assert stats["findings_digest_backfill"] >= 1
    await db.refresh(f_row)
    assert f_row.image_digest == f"sha256:{h}"


def test_iter_bulk_top_level_is_cyclonedx():
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "alpine:3.19"}},
        "components": [],
    }
    assert iter_cyclonedx_from_aikido_bulk_sbom(doc) == [(None, doc)]


def test_iter_bulk_sboms_list_with_nested_sbom():
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"component": {"name": "x:y"}},
        "components": [],
    }
    raw = {"sboms": [{"container_id": 99, "sbom": doc}]}
    pairs = iter_cyclonedx_from_aikido_bulk_sbom(raw)
    assert len(pairs) == 1
    assert pairs[0][0] == "99"
    assert pairs[0][1] == doc


@pytest.mark.asyncio
async def test_sync_bulk_generate_backfills_digest(db, monkeypatch):
    h = "d" * 64
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "name": "demo:2.0",
                "purl": f"pkg:oci/demo@sha256%3A{h}",
                "properties": [
                    {
                        "name": "aquasecurity:trivy:RepoDigest",
                        "value": f"demo@sha256:{h}",
                    },
                ],
            }
        },
        "components": [
            {
                "name": "openssl",
                "version": "3.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        ],
    }

    fp = f"fp-aikido-bulk-{uuid.uuid4().hex[:16]}"
    img = "docker.io/containers/images/aikido-bulk-test"
    f_row = Finding(
        id=f"f-{uuid.uuid4().hex[:10]}",
        finding_type=FindingType.SCA,
        fingerprint_id=fp,
        cve_id="CVE-2024-88888",
        severity=Severity.High,
        status=Status.Open,
        source="Aikido",
        image=img,
        tag="2.0",
        image_digest=None,
    )
    db.add(f_row)
    await db.commit()

    async def fake_bulk(ids, credentials=None):
        assert 55 in ids or ids == [55]
        return {"sboms": [{"container_id": 55, "sbom": cdx}]}

    monkeypatch.setattr(
        "app.services.aikido_container_sbom_sync.fetch_aikido_containers_sbom_bulk_generate",
        fake_bulk,
    )
    monkeypatch.setattr(
        "app.services.aikido_container_sbom_sync.get_settings",
        lambda: SimpleNamespace(
            aikido_container_sbom_sync=True,
            aikido_container_sbom_max_containers=0,
            aikido_container_sbom_bulk_generate=True,
            aikido_container_sbom_bulk_batch_size=10,
        ),
    )

    stats = await sync_aikido_container_sboms(
        db,
        {"client_id": "t", "client_secret": "s", "region": "eu"},
        [{"id": 55, "name": "containers/images/aikido-bulk-test:2.0"}],
    )

    assert stats["bulk_batches_ok"] >= 1
    assert stats["findings_digest_backfill"] >= 1
    await db.refresh(f_row)
    assert f_row.image_digest == f"sha256:{h}"
