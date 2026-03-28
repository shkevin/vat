"""
End-to-end correlation: real parsers + ingest path + PostgreSQL.

Uses committed golden reports under ``fixtures/correlation/`` (reproducible).
Source names mirror vat-local-scanner manual sources: ``vat-local-trivy``, ``vat-local-grype``, ``vat-local-gitleaks``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from app.api.ingest import _ingest_from_parser
from app.models.audit_event import AuditEvent
from app.models.finding import Finding

pytestmark = pytest.mark.integration_db

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "correlation"

TRACE = "trace-correlation-e2e-repro-001"


@pytest.mark.asyncio
async def test_trivy_then_grype_link_second_to_canonical(clean_integration_tables):
    """vat-local-trivy then vat-local-grype: same CVE/asset → correlated_to points to first finding."""
    db = clean_integration_tables
    trivy_raw = json.loads((FIXTURES / "trivy-e2e.json").read_text())
    grype_raw = json.loads((FIXTURES / "grype-e2e.json").read_text())

    r1 = await _ingest_from_parser(
        db,
        trivy_raw,
        "trivy",
        "vat-local-trivy",
        None,
        trace_id=TRACE,
        actor_id="vat-local-trivy",
    )
    r2 = await _ingest_from_parser(
        db,
        grype_raw,
        "grype",
        "vat-local-grype",
        None,
        trace_id=TRACE,
        actor_id="vat-local-grype",
    )
    assert r1.get("created", 0) >= 1
    assert r2.get("created", 0) >= 1

    rows = (
        (await db.execute(select(Finding).where(Finding.cve_id == "CVE-CORR-E2E-001")))
        .scalars()
        .all()
    )
    assert len(rows) == 2
    rows_sorted = sorted(rows, key=lambda f: (f.created_at, f.id))
    root, other = rows_sorted[0], rows_sorted[1]
    assert root.correlated_to is None
    assert other.correlated_to == root.id
    assert root.correlation_key == other.correlation_key

    ev = (
        (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.event_type == "dedup.correlation.linked",
                    AuditEvent.finding_id == other.id,
                )
            )
        )
        .scalars()
        .first()
    )
    assert ev is not None


@pytest.mark.asyncio
async def test_gitleaks_secret_does_not_link_to_sca_cluster(clean_integration_tables):
    """Secrets use a different correlation namespace than SCA; single finding → no_peer skipped."""
    db = clean_integration_tables
    raw = json.loads((FIXTURES / "gitleaks-e2e.json").read_text())
    await _ingest_from_parser(
        db,
        raw,
        "gitleaks",
        "vat-local-gitleaks",
        None,
        trace_id=TRACE + "-g",
        actor_id="vat-local-gitleaks",
    )
    f = (
        (
            await db.execute(
                select(Finding).where(Finding.source == "vat-local-gitleaks")
            )
        )
        .scalars()
        .first()
    )
    assert f is not None
    assert f.correlated_to is None
    ev = (
        (
            await db.execute(
                select(AuditEvent).where(
                    AuditEvent.finding_id == f.id,
                    AuditEvent.decision_reason_code == "no_peer",
                )
            )
        )
        .scalars()
        .first()
    )
    assert ev is not None
