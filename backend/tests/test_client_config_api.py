"""Tests for /api/config/container-aliases — public client config endpoint."""

import pytest

from app.core.config import get_settings


@pytest.mark.anyio
async def test_container_aliases_returns_settings_value(client, monkeypatch):
    """Endpoint mirrors VAT_CONTAINER_ASSET_PATH_ALIASES so the frontend can
    apply the same prefix rewrites the backend uses."""
    s = get_settings()
    expected = "docker.io/=>;ghcr.io/internal/=>"
    monkeypatch.setattr(s, "container_asset_path_aliases", expected)
    resp = await client.get("/api/config/container-aliases")
    assert resp.status_code == 200
    assert resp.json() == {"aliases": expected}


@pytest.mark.anyio
async def test_container_aliases_empty_when_unset(client, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "container_asset_path_aliases", "")
    resp = await client.get("/api/config/container-aliases")
    assert resp.status_code == 200
    assert resp.json() == {"aliases": ""}
