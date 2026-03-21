"""Cross-source correlation linking — unit tests (mocked DB)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.dialects import postgresql

from app.services.correlation_linking import apply_correlation_linking


@pytest.mark.asyncio
async def test_apply_correlation_linked_when_not_canonical():
    canonical = MagicMock()
    canonical.id = "f-old"
    subject = MagicMock()
    subject.id = "f-new"
    subject.correlation_key = "sca:asset:eco:comp:cve"
    subject.correlation_confidence = "high"
    subject.tenant_id = None

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
async def test_apply_correlation_medium_confidence_links():
    canonical = MagicMock()
    canonical.id = "f-a"
    subject = MagicMock()
    subject.id = "f-b"
    subject.correlation_key = "k"
    subject.correlation_confidence = "medium"
    subject.tenant_id = None

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
async def test_apply_correlation_skipped_low_confidence():
    subject = MagicMock()
    subject.id = "f-1"
    subject.correlation_key = "k"
    subject.correlation_confidence = "low"
    subject.tenant_id = None

    db = AsyncMock()
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ) as emit:
        await apply_correlation_linking(db, subject, "trace-1")
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["event_type"] == "dedup.correlation.skipped"
        assert (
            emit.await_args.kwargs["decision_reason_code"] == "confidence_below_policy"
        )


@pytest.mark.asyncio
async def test_apply_correlation_confidence_normalized_uppercase():
    subject = MagicMock()
    subject.id = "f-1"
    subject.correlation_key = "k"
    subject.correlation_confidence = "HIGH"
    subject.tenant_id = None

    canonical = MagicMock()
    canonical.id = "c1"
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
    other = MagicMock()
    other.id = "f-other"

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
    mid = MagicMock()
    mid.id = "f-2"
    mid.correlated_to = "bogus"
    leaf = MagicMock()
    leaf.id = "f-3"
    leaf.correlation_key = "k"
    leaf.correlation_confidence = "high"
    leaf.tenant_id = None

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
        assert emit.await_args.kwargs["decision_reason_code"] == "cluster_membership_mismatch"


@pytest.mark.asyncio
async def test_apply_correlation_tenant_scoped_execute_called_once():
    """Regression: tenant_id must be part of the cluster query (see contract tests)."""
    subject = MagicMock()
    subject.id = "f-a"
    subject.correlation_key = "same-key"
    subject.correlation_confidence = "high"
    subject.tenant_id = "tenant-1"

    peer = MagicMock()
    peer.id = "f-b"
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [peer, subject]

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    with patch(
        "app.services.correlation_linking.emit_audit_event", new_callable=AsyncMock
    ):
        await apply_correlation_linking(db, subject, "t1")

    db.execute.assert_awaited_once()
    call_stmt = db.execute.await_args[0][0]
    compiled = str(call_stmt.compile(dialect=postgresql.dialect())).lower()
    assert "findings.tenant_id" in compiled
    assert "tenant_id_1" in compiled or "%(tenant_id" in compiled
