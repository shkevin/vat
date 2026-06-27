"""Digest-conflict detection rules:

- Mutable/floating tags (latest, develop, branches) keep the latest observed
  digest and never raise a conflict (Aikido-style last-write-wins).
- Immutable tags (semver, sha-pinned) are vantage-aware: a cross-vantage digest
  difference (node-agent containerd vs registry pull, e.g. multi-arch index vs
  platform) is NOT a conflict; only a single vantage seeing two digests is.
"""

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


def test_mutable_tag_classification():
    for mut in ["latest", "develop", "main", "MASTER", "edge", "my-feature-branch", "", None]:
        assert obs._is_mutable_tag(mut) is True, mut
    for pinned in ["v1.19.4", "1.2.3", "8.9.1", "sha-228f19e7", "v8.18.0-dev", "20260627"]:
        assert obs._is_mutable_tag(pinned) is False, pinned


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeDB:
    """Routes by query: the conflict lookup vs the findings (source, digest)
    query, so it works for both the mutable and immutable code paths."""

    def __init__(self, finding_rows, existing_conflict=None):
        self._finding_rows = finding_rows
        self._existing = existing_conflict
        self.added = []
        self.deleted = []

    async def execute(self, query):
        if "asset_digest_conflicts" in str(query):
            return _Result([self._existing] if self._existing else [])
        return _Result(self._finding_rows)

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.deleted.append(obj)


_NOW = datetime(2026, 6, 27, 0, 0, 0)


@pytest.mark.asyncio
async def test_mutable_tag_keeps_latest_no_conflict():
    # :develop seen at two digests by the same vantage — expected drift, not a
    # conflict. Any existing row is cleared.
    stale = SimpleNamespace(digests=["sha256:aaa", "sha256:bbb"], status="open")
    db = _FakeDB(
        finding_rows=[("node-k3s-agent-1-trivy", "sha256:aaa")],
        existing_conflict=stale,
    )
    await obs._upsert_digest_conflict(
        db, asset_id="kamiwaza/images/core", tag="develop",
        digest="sha256:bbb", source="node-k3s-master-trivy", now=_NOW,
    )
    assert db.added == []
    assert db.deleted == [stale]


@pytest.mark.asyncio
async def test_immutable_cross_vantage_is_not_a_conflict_and_clears_stale_row():
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
async def test_immutable_same_vantage_two_digests_is_a_real_conflict():
    # A pinned tag served two digests to the same vantage = real supply-chain drift.
    db = _FakeDB(
        finding_rows=[("inventory-trivy", "sha256:aaa")],
        existing_conflict=None,
    )
    await obs._upsert_digest_conflict(
        db, asset_id="containers/images/app", tag="v2.0.0",
        digest="sha256:bbb", source="trivy", now=_NOW,
    )
    assert len(db.added) == 1
    assert sorted(db.added[0].digests) == ["sha256:aaa", "sha256:bbb"]
    assert db.deleted == []


@pytest.mark.asyncio
async def test_immutable_single_digest_no_conflict():
    db = _FakeDB(finding_rows=[], existing_conflict=None)
    await obs._upsert_digest_conflict(
        db, asset_id="containers/images/x", tag="v1.0.0",
        digest="sha256:aaa", source="inventory-trivy", now=_NOW,
    )
    assert db.added == [] and db.deleted == []
