"""Ingest API key service — generate, hash, validate, store. Design doc 2026-02-24."""

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.key_hashing import hash_key as _hash_key
from app.core.key_hashing import verify_key
from app.models.settings_model import SettingsKV

import hmac as _hmac


def _constant_time_compare(a: str, b: str) -> bool:
    """Back-compat helper for callers/tests that imported this directly."""
    return _hmac.compare_digest(a, b)

INGEST_KEYS_KEY = "ingest_api_keys"
KEY_PREFIX = "vat_"
KEY_PREFIX_LEN = 6  # "vat_a1" for display


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_key() -> tuple[str, str, str]:
    """
    Generate a new ingest API key.
    Returns (full_key, key_hash, key_prefix).
    """
    raw = secrets.token_hex(32)
    full_key = f"{KEY_PREFIX}{raw}"
    key_hash = _hash_key(full_key)
    key_prefix = full_key[:KEY_PREFIX_LEN]
    return full_key, key_hash, key_prefix


async def _get_keys_store(db: AsyncSession) -> dict:
    """Get ingest_api_keys from settings."""
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == INGEST_KEYS_KEY))
    row = r.scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return dict(row.value)
    return {}


def _utc_now_naive():
    """Naive UTC datetime for TIMESTAMP WITHOUT TIME ZONE columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _save_keys_store(db: AsyncSession, store: dict) -> None:
    """Save ingest_api_keys to settings."""
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == INGEST_KEYS_KEY))
    row = r.scalar_one_or_none()
    if row:
        row.value = store
        row.updated_at = _utc_now_naive()
    else:
        db.add(
            SettingsKV(key=INGEST_KEYS_KEY, value=store, updated_at=_utc_now_naive())
        )
    await db.commit()


async def _mutate_keys_store(db: AsyncSession, mutator):
    """Atomically read-modify-write the ingest key store under a row lock.

    Every scanner (node agents, inventory worker, CI) mints keys into this one
    SettingsKV blob. Without the lock, two concurrent minters each read the old
    blob and the second write drops the first's entry — the source then 401s.
    SELECT ... FOR UPDATE serialises the read-modify-write so entries survive.
    ponytail: assumes the row already exists (it does after first mint); a brand
    new store races only on the one-time bootstrap insert, which is harmless.
    """
    r = await db.execute(
        select(SettingsKV).where(SettingsKV.key == INGEST_KEYS_KEY).with_for_update()
    )
    row = r.scalar_one_or_none()
    store = dict(row.value) if row and isinstance(row.value, dict) else {}
    result = mutator(store)
    if row:
        row.value = store
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=INGEST_KEYS_KEY, value=store, updated_at=_utc_now_naive()))
    await db.commit()
    return result


@dataclass
class IngestKeyInfo:
    source_id: str
    key_prefix: str
    configured: bool
    auth_type: str = "api_token"
    created_at: Optional[str] = None
    rotated_at: Optional[str] = None


async def create_key(db: AsyncSession, source_id: str) -> tuple[str, str, str]:
    """
    Generate and store a new key for source_id.
    Returns (full_key, key_prefix, message).
    """
    source_id = (source_id or "").strip()
    if not source_id:
        raise ValueError("sourceId is required")

    full_key, key_hash, key_prefix = generate_key()

    def _mut(store: dict) -> None:
        store[source_id] = {
            "authType": "api_token",
            "keyHash": key_hash,
            "keyPrefix": key_prefix,
            "createdAt": _now(),
            "sourceId": source_id,
        }

    await _mutate_keys_store(db, _mut)
    return full_key, key_prefix, "Store this key securely. It will not be shown again."


async def regenerate_key(db: AsyncSession, source_id: str) -> tuple[str, str, str]:
    """Regenerate key for source_id. Returns (full_key, key_prefix, message)."""
    full_key, key_hash, key_prefix = generate_key()

    def _mut(store: dict) -> None:
        if source_id in store and isinstance(store[source_id], dict):
            store[source_id].update(
                {
                    "authType": "api_token",
                    "keyHash": key_hash,
                    "keyPrefix": key_prefix,
                    "createdAt": store[source_id].get("createdAt", _now()),
                    "rotatedAt": _now(),
                    "sourceId": source_id,
                }
            )
        else:
            store[source_id] = {
                "authType": "api_token",
                "keyHash": key_hash,
                "keyPrefix": key_prefix,
                "createdAt": _now(),
                "rotatedAt": _now(),
                "sourceId": source_id,
            }

    await _mutate_keys_store(db, _mut)
    return full_key, key_prefix, "Previous key invalidated. Store this key securely."


async def revoke_key(db: AsyncSession, source_id: str) -> bool:
    """Revoke key for source_id. Returns True if key existed."""

    def _mut(store: dict) -> bool:
        if source_id in store:
            del store[source_id]
            return True
        return False

    return await _mutate_keys_store(db, _mut)


async def list_keys(db: AsyncSession) -> list[IngestKeyInfo]:
    """List all keys (no secrets)."""
    store = await _get_keys_store(db)
    return [
        IngestKeyInfo(
            source_id=source_id,
            key_prefix=info.get("keyPrefix", "vat_"),
            configured=bool(info.get("keyHash")),
            auth_type=info.get("authType", "api_token"),
            created_at=info.get("createdAt"),
            rotated_at=info.get("rotatedAt"),
        )
        for source_id, info in store.items()
        if isinstance(info, dict) and info.get("keyHash")
    ]


async def validate_key(db: AsyncSession, key: str) -> Optional[tuple[str, str]]:
    """
    Validate key. Returns (source_id, user_attribution) if valid, else None.
    user_attribution: "ingest:<sourceId>" for audit.
    """
    if not key or not key.strip():
        return None
    key = key.strip()
    if not key.startswith(KEY_PREFIX):
        return None

    store = await _get_keys_store(db)

    for source_id, info in store.items():
        if not isinstance(info, dict):
            continue
        stored_hash = info.get("keyHash")
        if stored_hash and verify_key(key, stored_hash):
            return (source_id, f"ingest:{source_id}")

    return None
