"""Public client config endpoints — values the frontend needs to mirror backend.

These are intentionally unauthenticated and small; they expose deployment-wide
constants like container path aliases so the frontend can apply the same
canonicalization as the backend without baking values at build time.
"""

from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter()


@router.get("/container-aliases")
async def get_container_aliases() -> dict:
    """Return the configured container asset path alias rules.

    Mirrors backend ``apply_container_asset_path_aliases`` behavior so the
    frontend produces identical canonical asset keys (otherwise findings group
    differently and the asset list contains stripped/unstripped doubles).

    Format matches ``VAT_CONTAINER_ASSET_PATH_ALIASES``:
    ``"docker.io/=>;ghcr.io/internal/=>;registry-1.docker.io/=>"``.
    """
    return {"aliases": get_settings().container_asset_path_aliases or ""}
