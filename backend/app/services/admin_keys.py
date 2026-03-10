"""Admin API key service — long-lived keys for automation (scripts, CI)."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.settings_model import SettingsKV

ADMIN_KEYS_KEY = "admin_api_keys"
KEY_PREFIX = "vat_"
KEY_PREFIX_LEN = 6  # "vat_a1" for display


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def generate_admin_key() -> tuple[str, str, str]:
    """Generate a new admin API key. Returns (full_key, key_hash, key_prefix)."""
    raw = secrets.token_hex(32)
    full_key = f"{KEY_PREFIX}{raw}"
    key_hash = _hash_key(full_key)
    key_prefix = full_key[:KEY_PREFIX_LEN]
    return full_key, key_hash, key_prefix


def _next_id(store: dict) -> str:
    """Generate next id: ak_1, ak_2, ..."""
    used = {int(k.split("_")[1]) for k in store if isinstance(k, str) and k.startswith("ak_") and k[3:].isdigit()}
    n = 1
    while n in used:
        n += 1
    return f"ak_{n}"


async def _get_store(db: AsyncSession) -> dict:
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == ADMIN_KEYS_KEY))
    row = r.scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return dict(row.value)
    return {}


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _save_store(db: AsyncSession, store: dict) -> None:
    r = await db.execute(select(SettingsKV).where(SettingsKV.key == ADMIN_KEYS_KEY))
    row = r.scalar_one_or_none()
    if row:
        row.value = store
        row.updated_at = _utc_now_naive()
    else:
        db.add(SettingsKV(key=ADMIN_KEYS_KEY, value=store, updated_at=_utc_now_naive()))
    await db.commit()


@dataclass
class AdminKeyInfo:
    id: str
    key_prefix: str
    created_at: Optional[str] = None


async def create_admin_key(db: AsyncSession) -> tuple[str, str, str, str]:
    """
    Create a new admin API key.
    Returns (key_id, full_key, key_prefix, message).
    """
    full_key, key_hash, key_prefix = generate_admin_key()
    store = await _get_store(db)
    key_id = _next_id(store)
    store[key_id] = {
        "keyHash": key_hash,
        "keyPrefix": key_prefix,
        "createdAt": _now(),
    }
    await _save_store(db, store)
    return key_id, full_key, key_prefix, "Store this key securely. It will not be shown again."


async def revoke_admin_key(db: AsyncSession, key_id: str) -> bool:
    """Revoke admin key by id. Returns True if key existed."""
    store = await _get_store(db)
    if key_id in store:
        del store[key_id]
        await _save_store(db, store)
        return True
    return False


async def list_admin_keys(db: AsyncSession) -> list[AdminKeyInfo]:
    """List all admin keys (no secrets)."""
    store = await _get_store(db)
    return [
        AdminKeyInfo(
            id=key_id,
            key_prefix=info.get("keyPrefix", KEY_PREFIX),
            created_at=info.get("createdAt"),
        )
        for key_id, info in store.items()
        if isinstance(info, dict) and info.get("keyHash")
    ]


async def validate_admin_key(db: AsyncSession, key: str) -> bool:
    """
    Validate admin API key. Returns True if valid (grants admin role).
    """
    if not key or not key.strip():
        return False
    key = key.strip()
    if not key.startswith(KEY_PREFIX):
        return False

    key_hash = _hash_key(key)
    store = await _get_store(db)

    for info in store.values():
        if not isinstance(info, dict):
            continue
        stored_hash = info.get("keyHash")
        if stored_hash and _constant_time_compare(key_hash, stored_hash):
            return True

    return False
