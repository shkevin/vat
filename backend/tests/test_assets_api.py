"""Tests for assets API — admin-only delete from asset page."""

import bcrypt
import pytest
from sqlalchemy import text

from app.services.findings_service import create_findings_bulk


@pytest.fixture
async def assets_delete_setup(client, db):
    """Seed admin/reviewer users and one asset + finding to delete."""
    await db.execute(text("DELETE FROM correlation_edges"))
    has_digest_conflicts = await db.scalar(
        text("SELECT to_regclass('public.asset_digest_conflicts') IS NOT NULL")
    )
    has_observed_tags = await db.scalar(
        text("SELECT to_regclass('public.asset_observed_tags') IS NOT NULL")
    )
    if has_digest_conflicts:
        await db.execute(text("DELETE FROM asset_digest_conflicts"))
    if has_observed_tags:
        await db.execute(text("DELETE FROM asset_observed_tags"))
    await db.execute(text("DELETE FROM asset_merge_reviews"))
    await db.execute(text("DELETE FROM asset_merge_events"))
    await db.execute(text("DELETE FROM asset_aliases"))
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


async def _approve_merge_review(db, source_asset_id: str, target_asset_id: str) -> None:
    await db.execute(
        text(
            """
            INSERT INTO asset_merge_reviews
            (source_asset_id, target_asset_id, status, note, strategy, score, confidence, details, created_by, updated_by, created_at, updated_at)
            VALUES
            (:source_asset_id, :target_asset_id, 'approved', 'approved in test', 'manual', 1.0, 'high', '{}'::jsonb, 'reviewer@vat.local', 'reviewer@vat.local', NOW(), NOW())
            ON CONFLICT (source_asset_id, target_asset_id)
            DO UPDATE SET
              status = EXCLUDED.status,
              note = EXCLUDED.note,
              strategy = EXCLUDED.strategy,
              score = EXCLUDED.score,
              confidence = EXCLUDED.confidence,
              details = EXCLUDED.details,
              updated_by = EXCLUDED.updated_by,
              updated_at = NOW()
            """
        ),
        {"source_asset_id": source_asset_id, "target_asset_id": target_asset_id},
    )
    await db.commit()


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


@pytest.mark.asyncio
async def test_group_asset_merges_existing_findings_and_alias(
    client, db, assets_delete_setup
):
    """POST /api/assets/{id}/group reassigns findings and stores persistent alias."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "asset-merge-f1",
                "findingType": "SCA",
                "fingerprintId": "asset-merge-fp-1",
                "cveId": "CVE-2024-2222",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "asset-delete-test",
                "tag": "asset-delete-test",
                "title": "Merge-me finding",
                "source": "VAT",
            }
        ],
        replace=True,
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["target_asset_id"] == "asset-target"
    assert payload["alias_saved"] is True
    assert payload["findings_updated"] >= 1

    alias_target = await db.scalar(
        text(
            "SELECT canonical_asset_id FROM asset_aliases WHERE source_asset_id = 'asset-delete-test'"
        )
    )
    assert alias_target == "asset-target"

    updated_component = await db.scalar(
        text("SELECT component FROM findings WHERE id = 'asset-merge-f1'")
    )
    updated_tag = await db.scalar(
        text("SELECT tag FROM findings WHERE id = 'asset-merge-f1'")
    )
    assert updated_component == "asset-target"
    # Asset merge updates asset identity fields, not variant tags.
    assert updated_tag == "asset-delete-test"

    source_asset_count = await db.scalar(
        text("SELECT COUNT(*) FROM assets WHERE id = 'asset-delete-test'")
    )
    assert source_asset_count == 0


@pytest.mark.asyncio
async def test_group_asset_effectively_merges_duplicate_findings(
    client, db, assets_delete_setup
):
    """Merged asset findings are consolidated: moved duplicates become Duplicate + correlated."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await db.execute(text("DELETE FROM findings"))
    await db.execute(
        text(
            """
            INSERT INTO findings
            (id, finding_type, fingerprint_id, cve_id, severity, status, component_base, component, image, tag, title, source, needs_family_classification, sources, audit, tracker_comment, archived, external_links, regression_count, created_at, updated_at)
            VALUES
            ('asset-merge-src-dup', 'SCA', 'asset-merge-src-dup-fp', 'CVE-2024-4444', 'High', 'Open', 'openssl', 'openssl 3.0.0', 'asset-delete-test', 'asset-delete-test', 'merge duplicate source', 'trivy', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW()),
            ('asset-merge-target-canonical', 'SCA', 'asset-merge-target-canonical-fp', 'CVE-2024-9999', 'Medium', 'Open', 'openssl', 'openssl 3.0.0', 'asset-target', 'asset-target', 'merge duplicate target', 'Aikido', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW())
            """
        )
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["findings_updated"] >= 1
    assert payload["findings_merged"] >= 1

    moved = (
        await db.execute(
            text(
                "SELECT status, correlated_to, audit FROM findings WHERE id = 'asset-merge-src-dup'"
            )
        )
    ).first()
    assert moved is not None
    assert moved.status == "Duplicate"
    assert moved.correlated_to == "asset-merge-target-canonical"
    assert any(
        isinstance(entry, dict)
        and entry.get("action") == "Asset merge consolidated duplicate"
        for entry in (moved.audit or [])
    )


@pytest.mark.asyncio
async def test_group_asset_postpass_high_tier_links_moved_finding(
    client, db, assets_delete_setup
):
    """Moved findings run through the same high-tier linker policy after manual merge."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) VALUES "
            "('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await db.execute(text("DELETE FROM findings"))
    await db.execute(
        text(
            """
            INSERT INTO findings
            (id, finding_type, fingerprint_id, cve_id, severity, status, component_base, component, image, branch, tag, title, source, correlation_key, correlation_confidence, needs_family_classification, sources, audit, tracker_comment, archived, external_links, regression_count, created_at, updated_at)
            VALUES
            ('aa-high-target', 'SCA', 'aa-high-target-fp', 'CVE-2026-7001', 'High', 'Open', 'pkg-target', 'pkg target', 'asset-target', 'main', 'asset-target', 'target', 'Aikido', 'sca:merge-high:key', 'high', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW()),
            ('zz-high-source', 'SCA', 'zz-high-source-fp', 'CVE-2026-7001', 'High', 'Open', 'pkg-source', 'pkg source', 'asset-delete-test', 'main', 'asset-delete-test', 'source', 'trivy', 'sca:merge-high:key', 'high', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW())
            """
        )
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200

    moved = (
        await db.execute(
            text("SELECT correlated_to FROM findings WHERE id = 'zz-high-source'")
        )
    ).first()
    assert moved is not None
    assert moved.correlated_to == "aa-high-target"

    edge_count = await db.scalar(
        text(
            "SELECT COUNT(*) FROM correlation_edges "
            "WHERE active = true AND "
            "((finding_id_a = 'aa-high-target' AND finding_id_b = 'zz-high-source') "
            "OR (finding_id_a = 'zz-high-source' AND finding_id_b = 'aa-high-target'))"
        )
    )
    assert edge_count == 1


@pytest.mark.asyncio
async def test_group_asset_postpass_medium_tier_auto_links(
    client, db, assets_delete_setup
):
    """Moved findings that score medium after merge are auto-linked deterministically."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) VALUES "
            "('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await db.execute(text("DELETE FROM findings"))
    await db.execute(
        text(
            """
            INSERT INTO findings
            (id, finding_type, fingerprint_id, cve_id, severity, status, component_base, component, image, branch, tag, title, source, correlation_key, correlation_confidence, needs_family_classification, sources, audit, tracker_comment, archived, external_links, regression_count, created_at, updated_at)
            VALUES
            ('am-med-target', 'SCA', 'am-med-target-fp', '', 'High', 'Open', 'pkg-target', 'pkg target', 'asset-target', 'main', 'asset-target', 'target', 'Aikido', 'sca:merge-medium:key', 'medium', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW()),
            ('am-med-source', 'SCA', 'am-med-source-fp', '', 'High', 'Open', 'pkg-source', 'pkg source', 'asset-delete-test', 'main', 'asset-delete-test', 'source', 'trivy', 'sca:merge-medium:key', 'medium', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW())
            """
        )
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200

    moved = (
        await db.execute(
            text("SELECT correlated_to FROM findings WHERE id = 'am-med-source'")
        )
    ).first()
    target = (
        await db.execute(
            text("SELECT correlated_to FROM findings WHERE id = 'am-med-target'")
        )
    ).first()
    assert moved is not None and target is not None
    # Deterministic root is created_at,id ordered; either row may be root in tests.
    assert (
        moved.correlated_to == "am-med-target"
        or target.correlated_to == "am-med-source"
    )

    edge_count = await db.scalar(
        text(
            "SELECT COUNT(*) FROM correlation_edges "
            "WHERE active = true AND "
            "((finding_id_a = 'am-med-target' AND finding_id_b = 'am-med-source') "
            "OR (finding_id_a = 'am-med-source' AND finding_id_b = 'am-med-target'))"
        )
    )
    assert edge_count == 1


@pytest.mark.asyncio
async def test_group_asset_postpass_low_score_skips_moved_finding(
    client, db, assets_delete_setup
):
    """Moved findings that score low after merge are skipped (no edge, no review)."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) VALUES "
            "('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await db.execute(text("DELETE FROM findings"))
    await db.execute(
        text(
            """
            INSERT INTO findings
            (id, finding_type, fingerprint_id, cve_id, severity, status, component_base, component, image, branch, tag, title, source, correlation_key, correlation_confidence, needs_family_classification, sources, audit, tracker_comment, archived, external_links, regression_count, created_at, updated_at)
            VALUES
            ('aa-low-peer', 'SCA', 'aa-low-peer-fp', '', 'High', 'Open', 'pkg-peer', 'pkg peer', 'other-asset', 'main', 'other-asset', 'peer', 'Aikido', 'sca:merge-low:key', 'low', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW()),
            ('zz-low-source', 'SCA', 'zz-low-source-fp', '', 'High', 'Open', 'pkg-source', 'pkg source', 'asset-delete-test', 'main', 'asset-delete-test', 'source', 'trivy', 'sca:merge-low:key', 'low', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW())
            """
        )
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200

    moved = (
        await db.execute(
            text("SELECT correlated_to FROM findings WHERE id = 'zz-low-source'")
        )
    ).first()
    assert moved is not None
    assert moved.correlated_to is None

    edge_count = await db.scalar(
        text(
            "SELECT COUNT(*) FROM correlation_edges "
            "WHERE (finding_id_a = 'zz-low-source' OR finding_id_b = 'zz-low-source')"
        )
    )
    assert edge_count == 0


@pytest.mark.asyncio
async def test_group_asset_forbidden_for_non_admin(client, assets_delete_setup):
    """POST /api/assets/{id}/group returns 403 for reviewer role."""
    token = assets_delete_setup["reviewer_token"]
    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target"},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_group_asset_allows_admin_merge_without_review(
    client, db, assets_delete_setup
):
    token = assets_delete_setup["admin_token"]
    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await db.commit()

    res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["source_asset_id"] == "asset-delete-test"
    assert payload["target_asset_id"] == "asset-target"


@pytest.mark.asyncio
async def test_group_asset_container_matches_normalized_image_and_updates_findings(
    client,
    db,
    assets_delete_setup,
):
    """
    Merge source id may be path-only while findings store docker.io/... or :tag;
    reassignment must match the same container group key as the assets list.
    """
    token = assets_delete_setup["admin_token"]
    target_id = "docker.io/containers/images/extension-operator"
    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES (:id, :id, 'container', 'VAT')"
        ),
        {"id": target_id},
    )
    await db.execute(text("DELETE FROM findings"))
    await db.execute(
        text(
            """
            INSERT INTO findings
            (id, finding_type, fingerprint_id, cve_id, severity, status, component_base, component, image, tag, title, source, needs_family_classification, sources, audit, tracker_comment, archived, external_links, regression_count, created_at, updated_at)
            VALUES
            ('merge-cnorm-f1', 'SCA', 'merge-cnorm-fp', 'CVE-2024-7777', 'High', 'Open', 'openssl', 'openssl', 'docker.io/operators/images/extension-operator:v1', 'docker.io/operators/images/extension-operator:v1', 'norm merge', 'trivy', false, '[]'::jsonb, '[]'::jsonb, false, false, '[]'::jsonb, 0, NOW(), NOW())
            """
        )
    )
    await db.commit()

    res = await client.post(
        "/api/assets/operators/images/extension-operator/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": target_id, "reassign_existing_findings": True},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["findings_updated"] >= 1

    img = await db.scalar(
        text("SELECT image FROM findings WHERE id = 'merge-cnorm-f1'")
    )
    assert img == target_id


@pytest.mark.asyncio
async def test_unmerge_restores_alias_and_finding_mapping(
    client, db, assets_delete_setup
):
    """POST /api/assets/{canonical}/unmerge removes alias and restores merged finding fields."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('asset-target', 'asset-target', 'repo', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "asset-unmerge-f1",
                "findingType": "SCA",
                "fingerprintId": "asset-unmerge-fp-1",
                "cveId": "CVE-2024-3333",
                "severity": "High",
                "status": "Open",
                "componentBase": "openssl",
                "component": "asset-delete-test",
                "title": "Unmerge-me finding",
                "source": "VAT",
            }
        ],
        replace=True,
    )
    await db.commit()
    await _approve_merge_review(db, "asset-delete-test", "asset-target")

    merge_res = await client.post(
        "/api/assets/asset-delete-test/group",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_asset_id": "asset-target", "reassign_existing_findings": True},
    )
    assert merge_res.status_code == 200

    unmerge_res = await client.post(
        "/api/assets/asset-target/unmerge",
        headers={"Authorization": f"Bearer {token}"},
        json={"source_asset_id": "asset-delete-test"},
    )
    assert unmerge_res.status_code == 200
    payload = unmerge_res.json()
    assert payload["alias_removed"] is True
    assert payload["restored_findings"] >= 1

    alias_count = await db.scalar(
        text(
            "SELECT COUNT(*) FROM asset_aliases WHERE source_asset_id = 'asset-delete-test'"
        )
    )
    restored_component = await db.scalar(
        text("SELECT component FROM findings WHERE id = 'asset-unmerge-f1'")
    )
    assert alias_count == 0
    assert restored_component == "asset-delete-test"


@pytest.mark.asyncio
async def test_merge_suggestions_prefers_digest_then_ref(
    client, db, assets_delete_setup
):
    """GET /api/assets/{id}/merge-suggestions ranks digest > exact_ref."""
    token = assets_delete_setup["admin_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) VALUES "
            "('containers/images/extension-operator', 'containers/images/extension-operator', 'container', 'VAT'), "
            "('operators/images/extension-operator', 'operators/images/extension-operator', 'container', 'VAT'), "
            "('containers/images/extension-operator-alt', 'containers/images/extension-operator-alt', 'container', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "merge-sug-src-1",
                "findingType": "SCA",
                "fingerprintId": "merge-sug-src-fp-1",
                "cveId": "CVE-2026-0001",
                "severity": "High",
                "status": "Open",
                "componentBase": "grpc",
                "component": "grpc 1.72.0",
                "image": "containers/images/extension-operator",
                "tag": "release-0.11.0",
                "title": "source finding",
                "source": "trivy",
            },
            {
                "id": "merge-sug-digest-1",
                "findingType": "SCA",
                "fingerprintId": "merge-sug-digest-fp-1",
                "cveId": "CVE-2026-0001",
                "severity": "High",
                "status": "Open",
                "componentBase": "grpc",
                "component": "grpc 1.72.0",
                "image": "operators/images/extension-operator",
                "tag": "latest",
                "title": "digest peer finding",
                "source": "Aikido",
            },
            {
                "id": "merge-sug-ref-1",
                "findingType": "SCA",
                "fingerprintId": "merge-sug-ref-fp-1",
                "cveId": "CVE-2026-0002",
                "severity": "Medium",
                "status": "Open",
                "componentBase": "openssl",
                "component": "openssl 3.0.0",
                "image": "containers/images/extension-operator",
                "tag": "latest",
                "title": "ref peer finding",
                "source": "Aikido",
            },
        ],
        replace=True,
    )
    await db.execute(
        text(
            "UPDATE findings SET image_digest = :digest "
            "WHERE id IN ('merge-sug-src-1', 'merge-sug-digest-1')"
        ),
        {
            "digest": "sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
        },
    )
    await db.commit()

    res = await client.get(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-suggestions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["source_asset_id"] == "containers/images/extension-operator"
    assert payload["count"] >= 1
    first = payload["suggestions"][0]
    assert first["target_asset_id"] == "operators/images/extension-operator"
    assert first["strategy"] == "digest"
    assert first["confidence"] == "high"
    assert first["requires_review"] is True

    alias_count = await db.scalar(text("SELECT COUNT(*) FROM asset_aliases"))
    assert alias_count == 0


@pytest.mark.asyncio
async def test_merge_suggestions_allowed_for_reviewer(client, assets_delete_setup):
    """GET /api/assets/{id}/merge-suggestions is available to reviewer role."""
    token = assets_delete_setup["reviewer_token"]
    res = await client.get(
        "/api/assets/asset-delete-test/merge-suggestions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_merge_suggestions_include_finding_images_not_in_assets_table(
    client, db, assets_delete_setup
):
    """Candidates include image keys from findings even without persisted Asset rows."""
    token = assets_delete_setup["admin_token"]

    # Source asset exists in table.
    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) "
            "VALUES ('containers/images/extension-operator', 'containers/images/extension-operator', 'container', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "merge-sug-find-only-src",
                "findingType": "SCA",
                "fingerprintId": "merge-sug-find-only-src-fp",
                "cveId": "CVE-2026-1111",
                "severity": "High",
                "status": "Open",
                "componentBase": "grpc",
                "component": "grpc 1.72.0",
                "image": "containers/images/extension-operator",
                "tag": "release-0.11.0",
                "title": "source finding",
                "source": "trivy",
            },
            # Target image exists only in findings (no row in assets table).
            {
                "id": "merge-sug-find-only-target",
                "findingType": "SCA",
                "fingerprintId": "merge-sug-find-only-target-fp",
                "cveId": "CVE-2026-2222",
                "severity": "Medium",
                "status": "Open",
                "componentBase": "openssl",
                "component": "openssl 3.0.0",
                "image": "operators/images/extension-operator",
                "tag": "latest",
                "title": "target finding",
                "source": "Aikido",
            },
        ],
        replace=True,
    )
    await db.commit()

    res = await client.get(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-suggestions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    payload = res.json()
    target_ids = {s["target_asset_id"] for s in payload["suggestions"]}
    assert "operators/images/extension-operator" in target_ids


@pytest.mark.asyncio
async def test_merge_review_crud_and_suggestion_filtering(
    client, db, assets_delete_setup
):
    """Merge reviews support deny/reopen/delete and filter suggestion list by default."""
    token = assets_delete_setup["reviewer_token"]

    await db.execute(
        text(
            "INSERT INTO assets (id, name, type, source) VALUES "
            "('containers/images/extension-operator', 'containers/images/extension-operator', 'container', 'VAT')"
        )
    )
    await create_findings_bulk(
        db,
        [
            {
                "id": "merge-review-src-1",
                "findingType": "SCA",
                "fingerprintId": "merge-review-src-fp-1",
                "cveId": "CVE-2026-4001",
                "severity": "High",
                "status": "Open",
                "componentBase": "grpc",
                "component": "grpc 1.72.0",
                "image": "containers/images/extension-operator",
                "title": "source finding",
                "source": "trivy",
            },
            {
                "id": "merge-review-target-1",
                "findingType": "SCA",
                "fingerprintId": "merge-review-target-fp-1",
                "cveId": "CVE-2026-4001",
                "severity": "Medium",
                "status": "Open",
                "componentBase": "grpc",
                "component": "grpc 1.72.0",
                "image": "operators/images/extension-operator",
                "title": "target finding",
                "source": "Aikido",
            },
        ],
        replace=True,
    )
    await db.commit()

    deny = await client.put(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-reviews/operators%2Fimages%2Fextension-operator",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "status": "denied",
            "note": "Not ready",
            "strategy": "name_heuristic",
            "score": 1.0,
            "confidence": "medium",
            "details": {"reason": "manual deny"},
        },
    )
    assert deny.status_code == 200
    assert deny.json()["status"] == "denied"

    # Denied review should be hidden from default suggestions.
    filtered = await client.get(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-suggestions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert filtered.status_code == 200
    filtered_targets = {s["target_asset_id"] for s in filtered.json()["suggestions"]}
    assert "operators/images/extension-operator" not in filtered_targets

    # include_reviewed=true should surface denied suggestion.
    included = await client.get(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-suggestions?include_reviewed=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert included.status_code == 200
    included_targets = {s["target_asset_id"] for s in included.json()["suggestions"]}
    assert "operators/images/extension-operator" in included_targets

    # Reopen denied review (pending).
    reopen = await client.put(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-reviews/operators%2Fimages%2Fextension-operator",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "pending", "note": "reopened"},
    )
    assert reopen.status_code == 200
    assert reopen.json()["status"] == "pending"

    listed = await client.get(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-reviews",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1

    deleted = await client.delete(
        "/api/assets/containers%2Fimages%2Fextension-operator/merge-reviews/operators%2Fimages%2Fextension-operator",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


@pytest.mark.asyncio
async def test_digest_conflict_list_and_ack(client, db, assets_delete_setup):
    has_digest_conflicts = await db.scalar(
        text("SELECT to_regclass('public.asset_digest_conflicts') IS NOT NULL")
    )
    if not has_digest_conflicts:
        pytest.skip("asset_digest_conflicts table not available in this test database")

    token = assets_delete_setup["reviewer_token"]
    await db.execute(
        text(
            "INSERT INTO asset_digest_conflicts "
            "(asset_id, tag, status, digests, first_seen_at, last_seen_at) "
            "VALUES (:asset_id, :tag, 'open', CAST(:digests AS jsonb), NOW(), NOW())"
        ),
        {
            "asset_id": "asset-delete-test",
            "tag": "v1",
            "digests": '["sha256:aaaaaaaaaaaa","sha256:bbbbbbbbbbbb"]',
        },
    )
    await db.commit()

    listed = await client.get(
        "/api/assets/asset-delete-test/digest-conflicts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1

    ack = await client.put(
        "/api/assets/asset-delete-test/digest-conflicts/v1/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"acknowledged": True},
    )
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    reopen = await client.put(
        "/api/assets/asset-delete-test/digest-conflicts/v1/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"acknowledged": False},
    )
    assert reopen.status_code == 200
    assert reopen.json()["status"] == "open"
