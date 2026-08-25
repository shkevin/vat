"""Cross-source correlation linking — unit tests (mocked DB)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.dialects import postgresql

from app.services.correlation_linking import apply_correlation_linking


@pytest.mark.asyncio
async def test_apply_correlation_linked_when_not_canonical():
    canonical = MagicMock()
    canonical.id = "f-old"
    canonical.correlation_key = "v1:sca:asset:eco:comp:cve"
    canonical.image = "repo/app"
    canonical.branch = "main"
    canonical.tag = "v1"
    canonical.cve_id = "CVE-1"
    subject = MagicMock()
    subject.id = "f-new"
    subject.correlation_key = "v1:sca:asset:eco:comp:cve"
    subject.correlation_confidence = "high"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = "CVE-1"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [canonical, subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(
            db, subject, "trace-1", source_id="src-a", parser_id="trivy"
        )
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.linked"
        assert emit.await_args.kwargs["finding_id"] == "f-new"
        assert emit.await_args.kwargs["data"]["canonical_finding_id"] == "f-old"
    assert subject.correlated_to == "f-old"


@pytest.mark.asyncio
async def test_apply_correlation_medium_confidence_links_deterministically():
    canonical = MagicMock()
    canonical.id = "f-a"
    canonical.correlation_key = "k"
    canonical.image = "repo/app"
    canonical.branch = "main"
    canonical.tag = "v1"
    canonical.cve_id = None
    subject = MagicMock()
    subject.id = "f-b"
    subject.correlation_key = "k"
    subject.correlation_confidence = "medium"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [canonical, subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "t1")
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.linked"
    assert subject.correlated_to == "f-a"


@pytest.mark.asyncio
async def test_apply_correlation_skipped_no_peer_for_singleton_cluster():
    subject = MagicMock()
    subject.id = "f-1"
    subject.correlation_key = "k"
    subject.correlation_confidence = "low"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = "CVE-1"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "trace-1")
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.skipped"
        assert emit.await_args.kwargs["decision_reason_code"] == "no_peer"


@pytest.mark.asyncio
async def test_apply_correlation_confidence_normalized_uppercase():
    subject = MagicMock()
    subject.id = "f-1"
    subject.correlation_key = "k"
    subject.correlation_confidence = "HIGH"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = "CVE-1"

    canonical = MagicMock()
    canonical.id = "c1"
    canonical.correlation_key = "k"
    canonical.image = "repo/app"
    canonical.branch = "main"
    canonical.tag = "v1"
    canonical.cve_id = "CVE-1"
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [canonical, subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "t1")
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.linked"


@pytest.mark.asyncio
async def test_apply_correlation_skipped_no_correlation_key():
    subject = MagicMock()
    subject.id = "f-1"
    subject.correlation_key = None
    subject.correlation_confidence = "high"
    subject.tenant_id = None

    db = AsyncMock()
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "t1")
        assert emit.await_args.kwargs["decision_reason_code"] == "no_correlation_key"
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_apply_correlation_skipped_single_cluster_member():
    subject = MagicMock()
    subject.id = "f-only"
    subject.correlation_key = "k"
    subject.correlation_confidence = "high"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = "CVE-1"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "trace-1")
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.skipped"
        assert emit.await_args.kwargs["decision_reason_code"] == "no_peer"


@pytest.mark.asyncio
async def test_apply_correlation_skipped_canonical_root():
    canonical = MagicMock()
    canonical.id = "f-root"
    canonical.correlation_key = "k"
    canonical.correlation_confidence = "high"
    canonical.tenant_id = None
    canonical.image = "repo/app"
    canonical.branch = "main"
    canonical.tag = "v1"
    canonical.cve_id = "CVE-1"
    other = MagicMock()
    other.id = "f-other"
    other.image = "repo/app"
    other.branch = "main"
    other.tag = "v1"
    other.cve_id = "CVE-1"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [canonical, other]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, canonical, "trace-1")
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.skipped"
        assert emit.await_args.kwargs["decision_reason_code"] == "cluster_root"


@pytest.mark.asyncio
async def test_apply_correlation_three_node_cluster_repairs_stale_pointer():
    root = MagicMock()
    root.id = "f-1"
    root.correlation_key = "k"
    root.image = "repo/app"
    root.branch = "main"
    root.tag = "v1"
    root.cve_id = "CVE-1"
    mid = MagicMock()
    mid.id = "f-2"
    mid.correlation_key = "k"
    mid.correlated_to = "bogus"
    mid.image = "repo/app"
    mid.branch = "main"
    mid.tag = "v1"
    mid.cve_id = "CVE-1"
    leaf = MagicMock()
    leaf.id = "f-3"
    leaf.correlation_key = "k"
    leaf.correlation_confidence = "high"
    leaf.tenant_id = None
    leaf.image = "repo/app"
    leaf.branch = "main"
    leaf.tag = "v1"
    leaf.cve_id = "CVE-1"

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [root, mid, leaf]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ):
        await apply_correlation_linking(db, leaf, "t1")

    assert mid.correlated_to == "f-1"
    assert leaf.correlated_to == "f-1"


@pytest.mark.asyncio
async def test_apply_correlation_membership_mismatch_emits_and_returns():
    subject = MagicMock()
    subject.id = "f-subject"
    subject.correlation_key = "k"
    subject.correlation_confidence = "high"
    subject.tenant_id = None
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"

    other = MagicMock()
    other.id = "f-other-only"
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [other]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "t1")
        assert (
            emit.await_args.kwargs["decision_reason_code"]
            == "cluster_membership_mismatch"
        )


@pytest.mark.asyncio
async def test_apply_correlation_tenant_scoped_execute_called_once():
    """Regression: tenant_id must be part of the cluster query (see contract tests)."""
    subject = MagicMock()
    subject.id = "f-a"
    subject.correlation_key = "same-key"
    subject.correlation_confidence = "high"
    subject.tenant_id = "tenant-1"
    subject.image = "repo/app"
    subject.branch = "main"
    subject.tag = "v1"
    subject.cve_id = "CVE-1"

    peer = MagicMock()
    peer.id = "f-b"
    peer.correlation_key = "same-key"
    peer.image = "repo/app"
    peer.branch = "main"
    peer.tag = "v1"
    peer.cve_id = "CVE-1"
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [peer, subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ):
        await apply_correlation_linking(db, subject, "t1")

    assert db.execute.await_count >= 1
    call_stmt = db.execute.await_args_list[0].args[0]
    compiled = str(call_stmt.compile(dialect=postgresql.dialect())).lower()
    assert "findings.tenant_id" in compiled
    # The tenant must be *bound*, never inlined. Don't assert on the generated
    # bind-parameter name — it changes with how the clause is built (a plain
    # compare yields tenant_id_1, a COALESCE wrapper yields coalesce_2).
    params = call_stmt.compile(dialect=postgresql.dialect()).params
    assert subject.tenant_id in params.values()
