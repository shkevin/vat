"""Deterministic asset resolver for ingest payloads."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.vat import VatFindingSchema
from app.parsers.image_digest import effective_image_digest
from app.services.asset_aliases import resolve_canonical_asset_id
from app.services.container_ref_normalization import (
    apply_container_asset_path_aliases,
    normalize_container_ref,
)


@dataclass
class AssetResolution:
    asset_id: str
    asset_kind: str
    confidence: str
    reason: str
    source: str
    raw_asset_id: str | None = None
    observed_tag: str | None = None
    observed_digest: str | None = None

    def to_api_dict(self) -> dict:
        return asdict(self)


def _clean(value: Optional[str]) -> str:
    return str(value or "").strip()


def infer_asset_kind(asset_id: str, parser_id: str) -> str:
    aid = _clean(asset_id)
    pid = _clean(parser_id).lower()
    if not aid:
        return "unknown"
    if pid in ("openscap", "openscap_oval"):
        return "host_scope"
    if pid in ("semgrep", "sarif", "gitleaks"):
        return "path_scope"
    if pid in ("npm_audit", "pip_audit"):
        return "package_scope"
    if "/images/" in aid or aid.startswith("sha256:") or ":" in aid:
        return "container"
    if "/" in aid and not aid.startswith("/"):
        return "repo"
    if aid.startswith("/") or aid.startswith("commit:") or ">" in aid:
        return "path_scope"
    return "package_scope"


def resolve_asset_for_payload(
    payload: VatFindingSchema,
    *,
    parser_id: str,
    source_id: str,
    asset_override: Optional[str] = None,
    strict_mode: bool = False,
    requires_explicit_asset: bool = False,
) -> tuple[VatFindingSchema, AssetResolution]:
    """
    Resolve asset using precedence:
    1) explicit override
    2) payload.image
    3) payload.component
    4) payload.file_path
    """
    explicit = _clean(asset_override)
    img = _clean(payload.image)
    comp = _clean(payload.component)
    fpath = _clean(payload.file_path)

    raw_asset_id: str | None = None
    observed_tag: str | None = None
    observed_digest: str | None = None

    if explicit:
        asset_id = explicit
        raw_asset_id = explicit
        reason = "explicit_override"
        confidence = "explicit"
    elif img:
        asset_id = img
        raw_asset_id = img
        reason = "parser_image"
        confidence = "strong"
    elif comp:
        asset_id = comp
        reason = "parser_component_fallback"
        confidence = "medium"
    elif fpath:
        asset_id = f"path:{fpath}"
        reason = "parser_file_path_fallback"
        confidence = "weak"
    else:
        if strict_mode or requires_explicit_asset:
            raise ValueError(
                "Asset mapping failed: explicit asset required but no resolvable asset fields"
            )
        asset_id = "unknown"
        reason = "unknown_fallback"
        confidence = "weak"

    kind = infer_asset_kind(asset_id, parser_id)
    if kind == "container":
        raw_container_ref = asset_id
        normalized = normalize_container_ref(asset_id)
        asset_id = apply_container_asset_path_aliases(normalized.canonical_asset_key)
        observed_tag = normalized.observed_tag
        observed_digest = normalized.observed_digest
        # Prefer explicit image_digest, then @sha256 in raw ref, then parser split digest.
        merged_digest = effective_image_digest(
            getattr(payload, "image_digest", None),
            raw_container_ref,
        )
        if not merged_digest:
            merged_digest = observed_digest
        updates: dict[str, str | None] = {"image": asset_id}
        if not _clean(getattr(payload, "tag", None)) and observed_tag:
            updates["tag"] = observed_tag
        if merged_digest:
            updates["image_digest"] = merged_digest
        payload = payload.model_copy(update=updates)

    # Ensure deterministic image key for asset tables/filters.
    if explicit and img != asset_id:
        payload = payload.model_copy(update={"image": asset_id})
    elif (
        not img
        and asset_id not in ("unknown",)
        and reason.startswith("parser_file_path")
    ):
        payload = payload.model_copy(update={"image": asset_id})

    return payload, AssetResolution(
        asset_id=asset_id,
        asset_kind=kind,
        confidence=confidence,
        reason=reason,
        source=source_id,
        raw_asset_id=raw_asset_id,
        observed_tag=observed_tag,
        observed_digest=observed_digest,
    )


async def resolve_ingest_stub_asset_identity(
    db: AsyncSession,
    *,
    asset_hint: str,
    parser_id: str,
    source_asset_type: str | None,
) -> tuple[str, str]:
    """
    Zero-finding ingest creates an Asset row so clean scans still appear.

    Use the same container canonicalization as ``correlation_asset_image_for_ingest`` /
    ``resolve_asset_for_payload`` so stubs share ``Asset.id`` with findings (no duplicate
    ``containers/images/...`` vs ``docker.io/containers/images/...`` rows). For
    container identities, ``type`` is always ``container`` regardless of manual
    source defaults (e.g. trivy source configured as ``package``).
    """
    h = _clean(asset_hint)
    if not h:
        return h, source_asset_type or "package"

    kind = infer_asset_kind(h, parser_id)
    if kind == "container":
        cid = await correlation_asset_image_for_ingest(db, image=h, parser_id=parser_id)
        return cid, "container"

    cid = await resolve_canonical_asset_id(db, h)
    return cid, source_asset_type or "package"


async def correlation_asset_image_for_ingest(
    db: AsyncSession,
    *,
    image: str | None,
    parser_id: str | None,
) -> str:
    """
    Image segment for ``correlation_key`` asset part (``image|branch|tag``).

    Aligns all ingest entry points with HTTP ingest: canonical container registry path
    (``normalize_container_ref``) plus ``asset_aliases`` chain (``resolve_canonical_asset_id``).
    Non-container images pass through unchanged aside from alias resolution.
    """
    img = _clean(image)
    if not img:
        return ""
    kind = infer_asset_kind(img, parser_id or "")
    if kind == "container":
        img = apply_container_asset_path_aliases(
            normalize_container_ref(img).canonical_asset_key
        )
    return await resolve_canonical_asset_id(db, img)
