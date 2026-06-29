"""Tests for ingest API key service."""

import pytest
from sqlalchemy import update

from app.models.settings_model import SettingsKV
from app.services.ingest_keys import (
    INGEST_KEYS_KEY,
    create_key,
    generate_key,
    list_keys,
    regenerate_key,
    revoke_key,
    validate_key,
)


def test_generate_key_format():
    """Generated key has correct format."""
    full_key, key_hash, key_prefix = generate_key()
    assert full_key.startswith("vat_")
    assert len(full_key) == 4 + 64  # vat_ + 32 bytes hex
    assert key_prefix.startswith("vat_")
    # Hash format: "v2:<64 hex>" — HMAC-SHA256 with pepper from secret_key.
    # Legacy unprefixed sha256 hashes still validate via verify_key.
    assert key_hash.startswith("v2:")
    assert len(key_hash) == 3 + 64


@pytest.mark.asyncio
async def test_create_and_validate_key(db):
    """Create key, validate it, then fail with wrong key."""
    full_key, prefix, msg = await create_key(db, "trivy-ci")
    assert full_key.startswith("vat_")
    assert len(full_key) > 10
    assert prefix.startswith("vat_")

    result = await validate_key(db, full_key)
    assert result is not None
    source_id, user = result
    assert source_id == "trivy-ci"
    assert "trivy-ci" in user

    wrong = await validate_key(db, "vat_wrongkey123")
    assert wrong is None


async def _clear_ingest_keys(db):
    """Clear ingest_api_keys for test isolation."""
    await db.execute(
        update(SettingsKV).where(SettingsKV.key == INGEST_KEYS_KEY).values(value={})
    )
    await db.commit()


@pytest.mark.asyncio
async def test_list_keys(db):
    """Create keys, list them (no secrets)."""
    await _clear_ingest_keys(db)
    await create_key(db, "trivy-ci")
    await create_key(db, "github-actions")

    keys = await list_keys(db)
    assert len(keys) == 2
    source_ids = {k.source_id for k in keys}
    assert "trivy-ci" in source_ids
    assert "github-actions" in source_ids
    for k in keys:
        assert k.configured
        assert k.key_prefix.startswith("vat_")


@pytest.mark.asyncio
async def test_regenerate_invalidates_old(db):
    """Regenerate invalidates previous key."""
    old_key, _, _ = await create_key(db, "trivy-ci")
    new_key, _, _ = await regenerate_key(db, "trivy-ci")

    assert await validate_key(db, old_key) is None
    assert await validate_key(db, new_key) is not None


@pytest.mark.asyncio
async def test_regenerate_persists_across_reload(db):
    """Regression: a rotated key must survive a reload from the DB, not just the
    session's in-memory copy. _mutate_keys_store used to shallow-copy the store
    and mutate a nested dict in place, so SQLAlchemy saw no diff on the JSONB
    column and skipped the UPDATE — the new hash never persisted and every ingest
    401'd. expire_all() drops in-memory state so the next read hits the committed
    DB row, which is what the real ingest path (a separate request) sees."""
    await _clear_ingest_keys(db)
    old_key, _, _ = await create_key(db, "folder-scan-trivy")
    new_key, _, _ = await regenerate_key(db, "folder-scan-trivy")

    db.expire_all()

    assert await validate_key(db, new_key) is not None  # rotated key persisted
    assert await validate_key(db, old_key) is None  # old key invalidated


@pytest.mark.asyncio
async def test_revoke_key(db):
    """Revoke removes key."""
    full_key, _, _ = await create_key(db, "trivy-ci")
    assert await validate_key(db, full_key) is not None

    existed = await revoke_key(db, "trivy-ci")
    assert existed
    assert await validate_key(db, full_key) is None

    existed_again = await revoke_key(db, "trivy-ci")
    assert not existed_again


@pytest.mark.asyncio
async def test_create_key_requires_source_id(db):
    """Create key with empty sourceId raises."""
    with pytest.raises(ValueError, match="sourceId"):
        await create_key(db, "")
    with pytest.raises(ValueError, match="sourceId"):
        await create_key(db, "   ")
