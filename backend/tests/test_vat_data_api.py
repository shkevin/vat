"""Tests for VAT data API — findings + assets in one response."""

import bcrypt
import pytest
from sqlalchemy import text

from app.services.findings_service import create_findings_bulk


@pytest.fixture
async def vat_data_test_setup(client, db):
    """Seed tenant, user, and 3 findings (2 in one group, 1 in another) for vat-data tests."""
    await db.execute(text("DELETE FROM users"))
    await db.execute(text("DELETE FROM tenants"))
    await db.commit()

    pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
    await db.execute(
        text(
            "INSERT INTO tenants (id, name, created_at, auth_method) "
            "VALUES ('t-default', 'Default Org', NOW(), 'local')"
        )
    )
    await db.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, role, password_hash, created_at) "
            "VALUES ('admin', 't-default', 'admin@vat.local', 'admin', :pw, NOW()) "
            "ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, password_hash = EXCLUDED.password_hash"
        ),
        {"pw": pw_hash},
    )
    await db.commit()

    # 3 findings: 2 in same group (firefox-esr), 1 in another (openssl)
    findings = [
        {
            "id": "vat-test-f1",
            "findingType": "SCA",
            "fingerprintId": "fp-test-1",
            "cveId": "CVE-2024-8385",
            "severity": "High",
            "status": "Open",
            "componentBase": "firefox-esr",
            "component": "firefox-esr 115.0",
            "title": "Firefox CVE 1",
            "source": "VAT",
        },
        {
            "id": "vat-test-f2",
            "findingType": "SCA",
            "fingerprintId": "fp-test-2",
            "cveId": "CVE-2024-8381",
            "severity": "High",
            "status": "Open",
            "componentBase": "firefox-esr",
            "component": "firefox-esr 115.0",
            "title": "Firefox CVE 2",
            "source": "VAT",
        },
        {
            "id": "vat-test-f3",
            "findingType": "SCA",
            "fingerprintId": "fp-test-3",
            "cveId": "CVE-2024-5432",
            "severity": "Medium",
            "status": "Open",
            "componentBase": "openssl",
            "component": "openssl 3.0.0",
            "title": "OpenSSL CVE",
            "source": "VAT",
        },
    ]
    await create_findings_bulk(db, findings, replace=True)
    await db.commit()

    login_res = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    return {"token": token}


@pytest.mark.asyncio
async def test_vat_data_returns_all_findings(client, vat_data_test_setup):
    """GET /api/vat-data returns 3 findings when 3 exist (2 in one group, 1 in another)."""
    token = vat_data_test_setup["token"]
    res = await client.get(
        "/api/vat-data",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    findings = data.get("findings", [])
    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"
    # Verify groupKey: 2 findings share same group (firefox-esr), 1 is different (openssl)
    group_keys = [f.get("groupKey") for f in findings]
    assert (
        len(set(group_keys)) == 2
    ), f"Expected 2 unique groups, got {len(set(group_keys))}: {group_keys}"
