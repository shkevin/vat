"""Admin API key service — long-lived keys for automation (scripts, CI).

Keys can be tenant-bound (default) or cross-tenant. A tenant-bound key produces
a ``UserContext`` with ``tenant_id`` set; a cross-tenant key produces
``cross_tenant=True``. Legacy keys created before tenant binding existed have
neither field set; they are treated as cross-tenant for back-compat and a
warning is logged on validation so operators know to rotate them.
"""

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.settings_model import SettingsKV

logger = logging.getLogger(__name__)

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
    used = {
        int(k.split("_")[1])
        for k in store
        if isinstance(k, str) and k.startswith("ak_") and k[3:].isdigit()
    }
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
    tenant_id: Optional[str] = None
    cross_tenant: bool = False
    created_at: Optional[str] = None
    legacy: bool = False


@dataclass
class ResolvedAdminKey:
    """Result of validating an admin key. ``legacy=True`` means the key entry
    pre-dates tenant binding and should be rotated."""

    key_id: str
    tenant_id: Optional[str]
    cross_tenant: bool
    legacy: bool


async def create_admin_key(
    db: AsyncSession,
    *,
    tenant_id: Optional[str] = None,
    cross_tenant: bool = False,
) -> tuple[str, str, str, str]:
    """
    Create a new admin API key. Pass exactly one of ``tenant_id`` (tenant-bound)
    or ``cross_tenant=True`` (cross-tenant). Returns (key_id, full_key,
    key_prefix, message).
    """
    if cross_tenant and tenant_id is not None:
        raise ValueError("cross_tenant keys must not be bound to a tenant_id")
    if not cross_tenant and not tenant_id:
        raise ValueError("admin key requires either tenant_id or cross_tenant=True")

    full_key, key_hash, key_prefix = generate_admin_key()
    store = await _get_store(db)
    key_id = _next_id(store)
    store[key_id] = {
        "keyHash": key_hash,
        "keyPrefix": key_prefix,
        "tenantId": tenant_id,
        "crossTenant": bool(cross_tenant),
        "createdAt": _now(),
    }
    await _save_store(db, store)
    return (
        key_id,
        full_key,
        key_prefix,
        "Store this key securely. It will not be shown again.",
    )


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
    out: list[AdminKeyInfo] = []
    for key_id, info in store.items():
        if not isinstance(info, dict) or not info.get("keyHash"):
            continue
        legacy = "tenantId" not in info and "crossTenant" not in info
        out.append(
            AdminKeyInfo(
                id=key_id,
                key_prefix=info.get("keyPrefix", KEY_PREFIX),
                tenant_id=info.get("tenantId"),
                cross_tenant=bool(info.get("crossTenant", legacy)),
                created_at=info.get("createdAt"),
                legacy=legacy,
            )
        )
    return out


async def resolve_admin_key(db: AsyncSession, key: str) -> Optional[ResolvedAdminKey]:
    """Validate ``key`` and return its resolved scope. Returns None when invalid.

    A key entry without ``tenantId``/``crossTenant`` (created before tenant
    binding) is treated as ``cross_tenant=True`` and ``legacy=True``; callers
    should log/surface this so operators rotate the key.
    """
    if not key or not key.strip():
        return None
    key = key.strip()
    if not key.startswith(KEY_PREFIX):
        return None

    key_hash = _hash_key(key)
    store = await _get_store(db)

    for key_id, info in store.items():
        if not isinstance(info, dict):
            continue
        stored_hash = info.get("keyHash")
        if not stored_hash or not _constant_time_compare(key_hash, stored_hash):
            continue
        legacy = "tenantId" not in info and "crossTenant" not in info
        cross_tenant = bool(info.get("crossTenant", legacy))
        tenant_id = info.get("tenantId") if not cross_tenant else None
        if legacy:
            logger.warning(
                "admin key %s is legacy (no tenant binding); treating as cross_tenant. Rotate to a tenant-bound or explicit cross-tenant key.",
                key_id,
            )
        return ResolvedAdminKey(
            key_id=key_id,
            tenant_id=tenant_id,
            cross_tenant=cross_tenant,
            legacy=legacy,
        )

    return None


async def validate_admin_key(db: AsyncSession, key: str) -> bool:
    """Back-compat wrapper that returns True when the key resolves."""
    return await resolve_admin_key(db, key) is not None
