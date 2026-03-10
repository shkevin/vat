"""Tests for integration settings schemas API."""

import bcrypt
import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_integration_schemas_returns_sources_and_trackers(client, db):
    """GET /api/settings/integration-schemas returns schema-driven UI metadata."""
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default', NOW(), 'local') ON CONFLICT (id) DO NOTHING"
        )
    )
    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    login_res = await client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    res = await client.get(
        "/api/settings/integration-schemas",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "sources" in data
    assert "trackers" in data
    assert len(data["sources"]) >= 1
    assert len(data["trackers"]) >= 1

    aikido = next((s for s in data["sources"] if s["adapter_key"] == "aikido"), None)
    assert aikido is not None
    assert aikido["display_name"] == "Aikido"
    assert aikido["supports_test_connection"] is True
    assert any(f["key"] == "client_id" for f in aikido["fields"])
    assert any(f["key"] == "region" and f["type"] == "select" for f in aikido["fields"])
    assert aikido.get("brand_color") == "#10B981"
    assert aikido.get("icon") == "shield"
    assert "aikido" in (aikido.get("logo_url") or "")

    linear = next((t for t in data["trackers"] if t["adapter_key"] == "linear"), None)
    assert linear is not None
    assert linear["display_name"] == "Linear"
    assert any(f["key"] == "api_key" for f in linear["fields"])
    assert linear.get("brand_color") == "#5E6AD2"
    assert linear.get("icon") == "list-checks"

    # Flow types for diagram edges (VAT-defined)
    flow_types = data.get("flow_types", {})
    assert "ingest" in flow_types
    assert flow_types["ingest"]["color"] == "#10B981"
    assert flow_types["ingest"]["style"] == "dashed"
    assert flow_types["ingest"]["label"] == "Ingest"
    assert "sync_to_tracker" in flow_types
    assert "tracker_feedback" in flow_types
