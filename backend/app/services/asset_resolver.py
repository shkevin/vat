"""Deterministic asset resolver for ingest payloads."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from app.schemas.vat import VatFindingSchema


@dataclass
class AssetResolution:
    asset_id: str
    asset_kind: str
    confidence: str
    reason: str
    source: str

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

    if explicit:
        asset_id = explicit
        reason = "explicit_override"
        confidence = "explicit"
    elif img:
        asset_id = img
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
    )
