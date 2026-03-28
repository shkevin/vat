"""API tests for correlation crosswalk endpoints."""

import bcrypt
import pytest
from sqlalchemy import text

from app.services.findings_service import create_findings_bulk


@pytest.fixture
async def review_api_setup(client, db):
    await db.execute(text("DELETE FROM correlation_edges"))
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    admin_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
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
        {"admin_pw": admin_hash, "reviewer_pw": reviewer_hash},
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "corr-review-f1",
                "findingType": "SCA",
                "fingerprintId": "corr-review-fp-1",
                "cveId": "CVE-2026-0101",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "repo/app",
                "image": "repo/app",
                "branch": "main",
                "tag": "v1",
                "source": "VAT",
                "correlationKey": "v1:sca:repo/app:main:v1:npm:openssl:cve-2026-0101",
            },
            {
                "id": "corr-review-f2",
                "findingType": "SCA",
                "fingerprintId": "corr-review-fp-2",
                "cveId": "CVE-2026-0101",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "repo/app",
                "image": "repo/app",
                "branch": "main",
                "tag": "v1",
                "source": "VAT",
                "correlationKey": "v1:sca:repo/app:main:v1:npm:openssl:cve-2026-0101",
            },
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
async def test_crosswalk_run_and_resolve_api(client, review_api_setup):
    admin_headers = {"Authorization": f"Bearer {review_api_setup['admin_token']}"}
    reviewer_headers = {"Authorization": f"Bearer {review_api_setup['reviewer_token']}"}

    upsert = await client.post(
        "/api/findings/crosswalk/runs",
        json={
            "source": "unit",
            "source_version": "v1",
            "entries": [
                {
                    "from_namespace": "rule_id",
                    "from_value": "SV-8888",
                    "to_namespace": "stable_rule_key",
                    "to_value": "V-8888",
                    "confidence": "high",
                    "score": 0.9,
                    "metadata": {"seed": True},
                }
            ],
        },
        headers=admin_headers,
    )
    assert upsert.status_code == 200
    assert upsert.json()["status"] == "completed"

    resolved = await client.get(
        "/api/findings/crosswalk/resolve",
        params={
            "from_namespace": "rule_id",
            "from_value": "SV-8888",
            "to_namespace": "stable_rule_key",
        },
        headers=reviewer_headers,
    )
    assert resolved.status_code == 200
    r = resolved.json()
    assert r["count"] == 1
    assert r["mappings"][0]["to_value"] == "v-8888"

