"""OAuth client credentials for ingest — per-source client_id/client_secret."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.settings_model import SettingsKV

INGEST_OAUTH_CLIENTS_KEY = "ingest_oauth_clients"
OAUTH_CLIENT_ID_PREFIX = "vat_oauth_"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


async def _get_clients_store(db: AsyncSession) -> dict:
    r = await db.execute(
        select(SettingsKV).where(SettingsKV.key == INGEST_OAUTH_CLIENTS_KEY)
    )
    row = r.scalar_one_or_none()
    if row and isinstance(row.value, dict):
        return dict(row.value)
    return {}


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _save_clients_store(db: AsyncSession, store: dict) -> None:
    r = await db.execute(
        select(SettingsKV).where(SettingsKV.key == INGEST_OAUTH_CLIENTS_KEY)
    )
    row = r.scalar_one_or_none()
    if row:
        row.value = store
        row.updated_at = _utc_now_naive()
    else:
        db.add(
            SettingsKV(
                key=INGEST_OAUTH_CLIENTS_KEY, value=store, updated_at=_utc_now_naive()
            )
        )
    await db.commit()


def generate_client_credentials() -> tuple[str, str]:
    """Generate client_id and client_secret. Returns (client_id, client_secret)."""
    raw = secrets.token_hex(24)
    client_id = f"{OAUTH_CLIENT_ID_PREFIX}{raw[:16]}"
    client_secret = secrets.token_hex(32)
    return client_id, client_secret


@dataclass
class OAuthClientInfo:
    source_id: str
    client_id: str
    created_at: Optional[str]
    rotated_at: Optional[str]


async def create_oauth_client(db: AsyncSession, source_id: str) -> tuple[str, str, str]:
    """
    Create OAuth client for source_id.
    Returns (client_id, client_secret, message).
    Replaces any existing client for this source.
    """
    source_id = (source_id or "").strip()
    if not source_id:
        raise ValueError("sourceId is required")

    client_id, client_secret = generate_client_credentials()
    secret_hash = _hash_secret(client_secret)
    store = await _get_clients_store(db)
    store[source_id] = {
        "clientId": client_id,
        "clientSecretHash": secret_hash,
        "createdAt": _now(),
        "sourceId": source_id,
    }
    await _save_clients_store(db, store)
    return (
        client_id,
        client_secret,
        "Store client_secret securely. It will not be shown again.",
    )


async def validate_oauth_client(
    db: AsyncSession, client_id: str, client_secret: str
) -> Optional[tuple[str, str]]:
    """
    Validate client credentials. Returns (source_id, user_attribution) if valid, else None.
    """
    if not client_id or not client_secret or not client_id.strip():
        return None
    key = client_id.strip()
    if not key.startswith(OAUTH_CLIENT_ID_PREFIX):
        return None

    secret_hash = _hash_secret(client_secret)
    store = await _get_clients_store(db)

    for source_id, info in store.items():
        if not isinstance(info, dict):
            continue
        if info.get("clientId") == key and _constant_time_compare(
            secret_hash, info.get("clientSecretHash", "")
        ):
            return (source_id, f"ingest:{source_id}")

    return None


async def get_client_by_source(
    db: AsyncSession, source_id: str
) -> Optional[OAuthClientInfo]:
    """Get OAuth client info for source (no secrets)."""
    store = await _get_clients_store(db)
    info = store.get(source_id)
    if not isinstance(info, dict):
        return None
    return OAuthClientInfo(
        source_id=source_id,
        client_id=info.get("clientId", ""),
        created_at=info.get("createdAt"),
        rotated_at=info.get("rotatedAt"),
    )


async def rotate_oauth_client(db: AsyncSession, source_id: str) -> tuple[str, str, str]:
    """Regenerate client_secret for source_id. Invalidates old secret. Keeps same client_id."""
    source_id = (source_id or "").strip()
    if not source_id:
        raise ValueError("sourceId is required")

    store = await _get_clients_store(db)
    info = store.get(source_id)
    if not isinstance(info, dict):
        raise ValueError(f"No OAuth client for source {source_id}")

    client_id = info.get("clientId", "")
    _, client_secret = generate_client_credentials()
    secret_hash = _hash_secret(client_secret)
    info["clientSecretHash"] = secret_hash
    info["rotatedAt"] = _now()
    await _save_clients_store(db, store)
    return client_id, client_secret, "Previous secret invalidated. Store this securely."


async def revoke_oauth_client(db: AsyncSession, source_id: str) -> bool:
    """Revoke OAuth client for source_id. Returns True if existed."""
    store = await _get_clients_store(db)
    if source_id in store:
        del store[source_id]
        await _save_clients_store(db, store)
        return True
    return False


async def list_oauth_clients(db: AsyncSession) -> list[OAuthClientInfo]:
    """List all OAuth clients (no secrets)."""
    store = await _get_clients_store(db)
    return [
        OAuthClientInfo(
            source_id=source_id,
            client_id=info.get("clientId", ""),
            created_at=info.get("createdAt"),
            rotated_at=info.get("rotatedAt"),
        )
        for source_id, info in store.items()
        if isinstance(info, dict) and info.get("clientId")
    ]
