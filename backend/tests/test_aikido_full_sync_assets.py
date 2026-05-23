"""Aikido full-sync: ensure Asset rows are created for every finding's image.

Aikido's /issues/export surfaces findings against image variants (e.g.
``kamiwaza/images/core-dev``) that aren't in /containers. Before this fix
those rows ended up as orphan findings — visible in the findings filter but
not in the assets list. ``_ensure_asset_for_aikido_finding`` mirrors the
SBOM-side helper so the assets list reflects the full Aikido footprint.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.asset import Asset
from app.services.aikido_full_sync import (
    _ensure_asset_for_aikido_finding,
    _should_emit_aikido_ingest_progress,
)


def _mock_session(existing: dict[str, Asset] | None = None):
    existing = existing or {}
    added: list[Asset] = []

    async def get(model, key):
        return existing.get(key)

    session = SimpleNamespace(
        get=AsyncMock(side_effect=get),
        add=MagicMock(side_effect=lambda obj: added.append(obj)),
    )
    session._added = added  # type: ignore[attr-defined]
    return session


@pytest.mark.anyio
async def test_creates_container_asset_for_new_image() -> None:
    session = _mock_session()
    finding = SimpleNamespace(
        image="kamiwaza/images/core-dev", branch=None, component=None
    )
    created = await _ensure_asset_for_aikido_finding(session, finding)
    assert created is True
    assert len(session._added) == 1
    a = session._added[0]
    assert a.id == "kamiwaza/images/core-dev"
    assert a.type == "container"
    assert a.source == "Aikido"


@pytest.mark.anyio
async def test_creates_repo_asset_for_repo_shape() -> None:
    session = _mock_session()
    finding = SimpleNamespace(image="my-org/my-repo", branch="main", component=None)
    created = await _ensure_asset_for_aikido_finding(session, finding)
    assert created is True
    a = session._added[0]
    assert a.type == "repo"
    assert a.branch == "main"


@pytest.mark.anyio
async def test_skips_when_asset_already_exists() -> None:
    existing = Asset(
        id="containers/images/etcd",
        name="containers/images/etcd",
        type="container",
        source="Aikido",
    )
    session = _mock_session({"containers/images/etcd": existing})
    finding = SimpleNamespace(
        image="containers/images/etcd", branch=None, component=None
    )
    created = await _ensure_asset_for_aikido_finding(session, finding)
    assert created is False
    assert session._added == []


@pytest.mark.anyio
async def test_noop_when_finding_has_no_image() -> None:
    session = _mock_session()
    finding = SimpleNamespace(image=None, branch=None, component="some-pkg")
    created = await _ensure_asset_for_aikido_finding(session, finding)
    assert created is False
    assert session._added == []


def test_aikido_ingest_progress_is_rate_limited() -> None:
    total = 1201

    emitted = [
        processed
        for processed in range(1, total + 1)
        if _should_emit_aikido_ingest_progress(processed, total, interval=500)
    ]

    assert emitted == [1, 500, 1000, 1201]
