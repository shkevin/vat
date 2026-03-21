"""Normalize container image manifest digest for grouping (Docker Hub–style)."""

from __future__ import annotations

import re


def normalize_image_digest(value: str | None) -> str | None:
    """Return ``sha256:<64 hex>`` or None if invalid/too short."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip().lower()
    if not s:
        return None
    if s.startswith("sha256:"):
        hex_part = re.sub(r"[^0-9a-f]", "", s[7:])[:64]
    else:
        hex_part = re.sub(r"[^0-9a-f]", "", s)[:64]
    if len(hex_part) < 12:
        return None
    return f"sha256:{hex_part}"


def extract_digest_from_image_ref(image: str | None) -> str | None:
    """Parse ``registry/repo@sha256:...`` from stored image reference."""
    if not image or not isinstance(image, str) or "@sha256:" not in image:
        return None
    part = image.split("@sha256:", 1)[1]
    hex_part = re.sub(r"[^0-9a-f]", "", part.lower())[:64]
    if len(hex_part) < 12:
        return None
    return f"sha256:{hex_part}"


def effective_image_digest(
    payload_digest: str | None, image: str | None
) -> str | None:
    """Prefer explicit digest; else parse from image ref."""
    d = normalize_image_digest(payload_digest)
    if d:
        return d
    return extract_digest_from_image_ref(image)
