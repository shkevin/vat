"""Hashing for stored API keys / client secrets.

Bare ``hashlib.sha256(key).hexdigest()`` was used historically across
admin_keys / ingest_keys / oauth_clients. A DB read gave an attacker an
offline brute primitive: enumerate candidates, sha256 each, compare.
While 32-byte token_hex keys make brute infeasible in practice, there's
no defense in depth against shorter human-friendly keys or future
weakly-generated values, and there's no pepper to bind the hash to this
deployment.

This module produces ``v2:<hex>`` hashes computed as HMAC-SHA256(pepper,
key), where pepper is derived from ``settings.secret_key`` via a
constant-input HKDF-style domain separation. ``verify_key`` accepts
both the new ``v2:`` form and unprefixed legacy SHA-256 hashes so
existing entries keep validating until they're rotated.
"""

from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache

from app.core.config import get_settings

V2_PREFIX = "v2:"
_PEPPER_DOMAIN = b"vat-key-hash-v2"


@lru_cache(maxsize=1)
def _pepper() -> bytes:
    """Derive a pepper from ``secret_key``.

    Cached so we don't repeat the HMAC on every key validation. Bound to
    a domain string so a future re-use of ``secret_key`` for a different
    purpose cannot collide with this hash.
    """
    secret = get_settings().secret_key.encode("utf-8")
    return hmac.new(secret, _PEPPER_DOMAIN, hashlib.sha256).digest()


def hash_key(key: str) -> str:
    """Hash an API key / client secret for at-rest storage.

    Returns ``v2:<hex>`` where hex is HMAC-SHA256(pepper, key).
    """
    digest = hmac.new(_pepper(), key.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{V2_PREFIX}{digest}"


def _legacy_hash(key: str) -> str:
    """The pre-pepper SHA-256 hex digest used by entries created before this
    module existed. Kept here so verify_key can accept legacy stored hashes
    until they're rotated to v2."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_key(key: str, stored_hash: str) -> bool:
    """Constant-time check ``key`` against ``stored_hash``.

    Accepts both the new ``v2:`` form and unprefixed legacy SHA-256.
    """
    if not stored_hash:
        return False
    if stored_hash.startswith(V2_PREFIX):
        candidate = hash_key(key)
        return hmac.compare_digest(candidate, stored_hash)
    # Legacy bare SHA-256 hash.
    candidate = _legacy_hash(key)
    return hmac.compare_digest(candidate, stored_hash)
