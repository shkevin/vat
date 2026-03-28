"""Container reference normalization for canonical asset identity."""

from __future__ import annotations

from dataclasses import dataclass

from app.parsers.image_digest import normalize_image_digest


def _parse_container_asset_path_aliases(raw: str) -> list[tuple[str, str]]:
    """Parse ``VAT_CONTAINER_ASSET_PATH_ALIASES``: ``from=>to;from2=>to2``."""
    out: list[tuple[str, str]] = []
    if not raw or not str(raw).strip():
        return out
    for segment in str(raw).split(";"):
        segment = segment.strip()
        if "=>" not in segment:
            continue
        left, right = segment.split("=>", 1)
        src = left.strip().lower()
        dst = right.strip().lower()
        if src and dst:
            out.append((src, dst))
    return out


def apply_container_asset_path_aliases(canonical_key: str) -> str:
    """
    Rewrite canonical registry path prefixes (tenant policy).

    Applied after ``normalize_container_ref`` so scanner ``.../operators/images/...``
    and Aikido ``.../containers/images/...`` can map to one asset key when configured.
    """
    if not canonical_key or not canonical_key.strip():
        return canonical_key
    from app.core.config import get_settings

    pairs = _parse_container_asset_path_aliases(
        get_settings().container_asset_path_aliases or ""
    )
    if not pairs:
        return canonical_key
    k = canonical_key.strip()
    lower = k.lower()
    for src, dst in pairs:
        if lower.startswith(src):
            return dst + k[len(src) :]
    return canonical_key


@dataclass(frozen=True)
class NormalizedContainerRef:
    canonical_asset_key: str
    observed_tag: str | None
    observed_digest: str | None
    raw_ref: str


def _split_digest(ref: str) -> tuple[str, str | None]:
    if "@sha256:" not in ref:
        return ref, None
    left, right = ref.split("@sha256:", 1)
    digest = normalize_image_digest(f"sha256:{right}")
    return left.strip(), digest


def _split_tag(repo_ref: str) -> tuple[str, str | None]:
    if ":" not in repo_ref:
        return repo_ref, None
    last_slash = repo_ref.rfind("/")
    last_colon = repo_ref.rfind(":")
    if last_colon > last_slash:
        tag = repo_ref[last_colon + 1 :].strip()
        if tag:
            return repo_ref[:last_colon].strip(), tag
    return repo_ref, None


def _split_registry_and_path(repo: str) -> tuple[str | None, str]:
    if not repo:
        return None, ""
    if "/" not in repo:
        return None, repo
    first, rest = repo.split("/", 1)
    if "." in first or ":" in first or first == "localhost":
        return first, rest
    return None, repo


def _docker_hub_path(path: str) -> str:
    p = (path or "").strip("/")
    if not p:
        return "library/unknown"
    if "/" not in p:
        return f"library/{p}"
    return p


def normalize_container_ref(value: str | None) -> NormalizedContainerRef:
    raw = (value or "").strip()
    if not raw:
        return NormalizedContainerRef(
            canonical_asset_key="docker.io/library/unknown",
            observed_tag=None,
            observed_digest=None,
            raw_ref="",
        )

    repo_tag_part, digest = _split_digest(raw)
    repo_part, tag = _split_tag(repo_tag_part)
    registry, path = _split_registry_and_path(repo_part)

    if registry is None:
        registry = "docker.io"
        path = _docker_hub_path(path)

    canonical = f"{registry.lower()}/{(path or '').strip('/').lower()}".strip("/")
    if not canonical:
        canonical = "docker.io/library/unknown"

    return NormalizedContainerRef(
        canonical_asset_key=canonical,
        observed_tag=(tag or None),
        observed_digest=digest,
        raw_ref=raw,
    )


def is_safe_tag_only_alias_variant(raw_ref: str | None, canonical_asset_key: str) -> bool:
    """
    True when raw_ref differs from canonical only by an explicit tag.

    Requires:
    - same normalized canonical key
    - tag present
    - no digest in raw ref
    """

    raw = (raw_ref or "").strip()
    canonical = (canonical_asset_key or "").strip().lower()
    if not raw or not canonical:
        return False
    normalized = normalize_container_ref(raw)
    if normalized.canonical_asset_key != canonical:
        return False
    return bool(normalized.observed_tag and not normalized.observed_digest)
