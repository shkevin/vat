"""Integration coverage for multi-cluster attribution (X-VAT-Cluster).

Same image CVE from two clusters -> ONE deduped finding whose observed_clusters
enumerate both clusters, with one observation row per (cluster, scan session).
Plus the cluster->tenant map (Layer 3) routing a cluster's findings to a tenant.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from app.api.ingest import _ingest_from_parser
from app.core.config import get_settings
from app.models.finding import Finding
from app.models.finding_observation import FindingObservation

pytestmark = pytest.mark.integration_db


async def _reset(db) -> None:
    await db.execute(text("TRUNCATE TABLE finding_observations RESTART IDENTITY CASCADE"))
    await db.execute(text("TRUNCATE TABLE findings RESTART IDENTITY CASCADE"))
    await db.commit()


def _payload() -> dict:
    return {
        "findings": [
            {
                "cve_id": "CVE-CLUSTER-001",
                "severity": "High",
                "description": "shared image vuln",
                "finding_type": "SCA",
                "component": "openssl 1.1.1",
                "image": "ghcr.io/acme/core:v1.0.0",
            }
        ]
    }


@pytest.mark.asyncio
async def test_same_image_two_clusters_dedups_with_both_attributed(clean_integration_tables):
    db = clean_integration_tables
    await _reset(db)

    await _ingest_from_parser(
        db, _payload(), "canonical", "inventory-trivy", None,
        scan_session_id="sess-east", cluster_id="prod-east",
    )
    await _ingest_from_parser(
        db, _payload(), "canonical", "inventory-trivy", None,
        scan_session_id="sess-west", cluster_id="prod-west",
    )
    await db.commit()

    findings = (await db.execute(select(Finding))).scalars().all()
    assert len(findings) == 1, "same image CVE must dedup to one finding across clusters"
    assert sorted(findings[0].observed_clusters) == ["prod-east", "prod-west"]

    obs = (await db.execute(select(FindingObservation))).scalars().all()
    assert {o.cluster_id for o in obs} == {"prod-east", "prod-west"}


@pytest.mark.asyncio
async def test_cluster_tenant_map_routes_findings(clean_integration_tables, monkeypatch):
    db = clean_integration_tables
    await _reset(db)
    monkeypatch.setattr(get_settings(), "cluster_tenant_map", {"prod-east": "t-acme"})

    await _ingest_from_parser(
        db, _payload(), "canonical", "inventory-trivy", None,
        scan_session_id="sess-east", cluster_id="prod-east",
    )
    await db.commit()

    finding = (await db.execute(select(Finding))).scalars().one()
    assert finding.tenant_id == "t-acme"
