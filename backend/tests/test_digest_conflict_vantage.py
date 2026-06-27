"""Digest-conflict detection is vantage-aware: cross-vantage digest differences
(node-agent containerd vs registry-pull, e.g. multi-arch index vs platform) are
NOT conflicts; only a single vantage seeing two digests for a tag is."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services import container_asset_observations as obs


def test_vantage_classification():
    assert obs._digest_scan_vantage("node-k3s-agent-1-trivy") == "runtime"
    assert obs._digest_scan_vantage("node-k3s-master-cyclonedx") == "runtime"
    assert obs._digest_scan_vantage("inventory-trivy") == "registry"
    assert obs._digest_scan_vantage("trivy") == "registry"
    assert obs._digest_scan_vantage("Aikido") == "registry"
    assert obs._digest_scan_vantage(None) == "registry"


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeDB:
    """First execute() answers the findings (source, digest) query, second the
    existing-conflict lookup."""

    def __init__(self, finding_rows, existing_conflict=None):
        self._finding_rows = finding_rows
        self._existing = existing_conflict
        self._n = 0
        self.added = []
        self.deleted = []

    async def execute(self, _query):
        self._n += 1
        if self._n == 1:
            return _Result(self._finding_rows)
        return _Result([self._existing] if self._existing else [])

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.deleted.append(obj)


_NOW = datetime(2026, 6, 27, 0, 0, 0)


@pytest.mark.asyncio
async def test_cross_vantage_is_not_a_conflict_and_clears_stale_row():
    # node-agent (containerd) and worker (registry) report different digests for
    # the same pinned tag — multi-arch representation, not real drift.
    stale = SimpleNamespace(digests=["sha256:aaa", "sha256:bbb"], status="open")
    db = _FakeDB(
        finding_rows=[("node-k3s-agent-2-trivy", "sha256:aaa")],
        existing_conflict=stale,
    )
    await obs._upsert_digest_conflict(
        db, asset_id="containers/images/cert-manager", tag="v1.19.4",
        digest="sha256:bbb", source="inventory-trivy", now=_NOW,
    )
    assert db.added == []
    assert db.deleted == [stale]  # false positive cleared


@pytest.mark.asyncio
async def test_same_vantage_two_digests_is_a_real_conflict():
    # two node agents (same runtime vantage) cached different builds of :develop
    db = _FakeDB(
        finding_rows=[("node-k3s-agent-1-trivy", "sha256:aaa")],
        existing_conflict=None,
    )
    await obs._upsert_digest_conflict(
        db, asset_id="kamiwaza/images/core", tag="develop",
        digest="sha256:bbb", source="node-k3s-master-trivy", now=_NOW,
    )
    assert len(db.added) == 1
    assert sorted(db.added[0].digests) == ["sha256:aaa", "sha256:bbb"]
    assert db.deleted == []


@pytest.mark.asyncio
async def test_single_digest_no_conflict():
    db = _FakeDB(finding_rows=[], existing_conflict=None)
    await obs._upsert_digest_conflict(
        db, asset_id="containers/images/x", tag="v1",
        digest="sha256:aaa", source="inventory-trivy", now=_NOW,
    )
    assert db.added == [] and db.deleted == []
