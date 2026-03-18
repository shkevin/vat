"""Tests for assets API — admin-only delete from asset page."""

import bcrypt
import pytest
from sqlalchemy import text

from app.services.findings_service import create_findings_bulk


@pytest.fixture
async def assets_delete_setup(client, db):
    """Seed admin/reviewer users and one asset + finding to delete."""
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM assets"))
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
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
            "VALUES "
            "('admin', 't-default', 'admin@vat.local', 'admin', :admin_pw, NOW()), "
            "('reviewer', 't-default', 'reviewer@vat.local', 'reviewer', :reviewer_pw, NOW())"
        ),
        {"admin_pw": pw_hash, "reviewer_pw": reviewer_hash},
    )
    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('asset-delete-test', 'asset-delete-test', 'repo', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "asset-del-f1",
                "findingType": "SCA",
                "fingerprintId": "asset-del-fp-1",
                "cveId": "CVE-2024-1111",
                "severity": "High",
                "status": "Open",
                "componentBase": "asset-delete-test",
                "component": "asset-delete-test",
                "title": "Delete-me finding",
                "source": "VAT",
            }
        ],
        replace=True,
    )
    await db.commit()

    admin_login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    reviewer_login = await client.post(
        "/api/auth/login",
        json={"username": "reviewer", "password": "reviewer"},
    )
    assert admin_login.status_code == 200
    assert reviewer_login.status_code == 200
    return {
        "admin_token": admin_login.json()["token"],
        "reviewer_token": reviewer_login.json()["token"],
    }


@pytest.mark.asyncio
async def test_delete_asset_removes_asset_and_findings(client, db, assets_delete_setup):
    """DELETE /api/assets/{id} removes the asset row and matching findings for admins."""
    token = assets_delete_setup["admin_token"]
    res = await client.delete(
        "/api/assets/asset-delete-test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["deleted_asset"] is True
    assert payload["deleted_findings"] >= 1

    findings_count = await db.scalar(text("SELECT COUNT(*) FROM findings"))
    assets_count = await db.scalar(
        text("SELECT COUNT(*) FROM assets WHERE id = 'asset-delete-test'")
    )
    assert findings_count == 0
    assert assets_count == 0


@pytest.mark.asyncio
async def test_delete_asset_forbidden_for_non_admin(client, db, assets_delete_setup):
    """DELETE /api/assets/{id} returns 403 for reviewer role."""
    token = assets_delete_setup["reviewer_token"]
    res = await client.delete(
        "/api/assets/asset-delete-test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
