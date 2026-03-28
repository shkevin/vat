"""API tests for reversible correlation edges."""

import bcrypt
import pytest
from sqlalchemy import text

from app.services.correlation_edges import upsert_edge
from app.services.findings_service import create_findings_bulk


@pytest.fixture
async def correlation_api_setup(client, db):
    has_edges = await db.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'correlation_edges')"
        )
    )
    if not has_edges:
        pytest.skip("correlation_edges table missing; run migrations first")

    await db.execute(text("DELETE FROM correlation_edges"))
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    reviewer_hash = bcrypt.hashpw(b"reviewer", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default Org', NOW(), 'local')"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('reviewer', 't-default', 'reviewer@vat.local', 'reviewer', :pw, NOW())"
        ),
        {"pw": reviewer_hash},
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "corr-api-f1",
                "findingType": "SCA",
                "fingerprintId": "corr-api-fp-1",
                "cveId": "CVE-2024-1010",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "svc-a",
                "source": "VAT",
            },
            {
                "id": "corr-api-f2",
                "findingType": "SCA",
                "fingerprintId": "corr-api-fp-2",
                "cveId": "CVE-2024-1010",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "svc-a",
                "source": "VAT",
            },
        ],
        replace=True,
    )
    await upsert_edge(
        db,
        finding_id_left="corr-api-f1",
        finding_id_right="corr-api-f2",
        edge_type="same_control",
        confidence="medium",
        evidence={"seed": True},
        created_by="seed",
    )
    await db.commit()

    login = await client.post(
        "/api/auth/login",
        json={"username": "reviewer", "password": "reviewer"},
    )
    assert login.status_code == 200
    return {"token": login.json()["token"]}


@pytest.mark.asyncio
async def test_remove_restore_and_history(client, correlation_api_setup):
    token = correlation_api_setup["token"]
    headers = {"Authorization": f"Bearer {token}"}

    removed = await client.post(
        "/api/findings/corr-api-f1/correlations/corr-api-f2/remove",
        json={"reason": "manual review says split"},
        headers=headers,
    )
    assert removed.status_code == 200
    assert removed.json()["deactivated"] is True

    restored = await client.post(
        "/api/findings/corr-api-f1/correlations/corr-api-f2/restore",
        json={"reason": "follow-up confirms same control"},
        headers=headers,
    )
    assert restored.status_code == 200
    assert restored.json()["restored"] is True

    history = await client.get(
        "/api/findings/corr-api-f1/correlations/history",
        headers=headers,
    )
    assert history.status_code == 200
    payload = history.json()
    assert payload["count"] >= 1
    edge = payload["edges"][0]
    assert edge["peer_finding_id"] == "corr-api-f2"
    assert edge["active"] is True
    assert edge["operation_id"]

    listed = await client.get(
        "/api/findings/corr-api-f1/correlations",
        headers=headers,
    )
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["count"] >= 1
    assert listed_payload["edges"][0]["peer_finding_id"] == "corr-api-f2"

    op_lookup = await client.get(
        f"/api/findings/correlations/operations/{edge['operation_id']}",
        headers=headers,
    )
    assert op_lookup.status_code == 200
    op_payload = op_lookup.json()
    assert op_payload["count"] >= 1
    assert op_payload["edges"][0]["operation_id"] == edge["operation_id"]


@pytest.mark.asyncio
async def test_correlation_endpoints_not_found_paths(client, correlation_api_setup):
    token = correlation_api_setup["token"]
    headers = {"Authorization": f"Bearer {token}"}

    missing_remove = await client.post(
        "/api/findings/corr-api-f1/correlations/missing-f/remove",
        json={"reason": "none"},
        headers=headers,
    )
    assert missing_remove.status_code == 404

    missing_restore = await client.post(
        "/api/findings/corr-api-f1/correlations/missing-f/restore",
        json={"reason": "none"},
        headers=headers,
    )
    assert missing_restore.status_code == 404

    missing_history = await client.get(
        "/api/findings/missing-f/correlations/history",
        headers=headers,
    )
    assert missing_history.status_code == 404

    empty_operation = await client.get(
        "/api/findings/correlations/operations/op-does-not-exist",
        headers=headers,
    )
    assert empty_operation.status_code == 200
    assert empty_operation.json()["count"] == 0

