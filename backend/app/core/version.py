"""Package version for export manifests and diagnostics."""

from __future__ import annotations

from pathlib import Path


def get_vat_backend_version() -> str:
    try:
        from importlib.metadata import version

        return version("vat-backend")
    except Exception:
        pass
    try:
        import tomllib

        root = Path(__file__).resolve().parents[2]
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        ver = data.get("project", {}).get("version")
        if isinstance(ver, str) and ver:
            return ver
    except Exception:
        pass
    return "0.0.0-dev"
