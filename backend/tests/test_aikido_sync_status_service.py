from datetime import datetime, timedelta, timezone

from app.services.aikido_sync_status import (
    AIKIDO_FULL_SYNC_TOTAL_STEPS,
    build_running_aikido_sync_status,
    coerce_stale_running_status,
)


def test_running_status_is_restorable_immediately_after_enqueue():
    status = build_running_aikido_sync_status(
        "source-1",
        message="Sync queued.",
        started_at="2026-05-23T12:00:00Z",
    )

    assert status["status"] == "running"
    assert status["source_id"] == "source-1"
    assert status["step"] == 0
    assert status["total"] == AIKIDO_FULL_SYNC_TOTAL_STEPS
    assert status["label"] == "Queued"


def test_stale_running_status_is_reported_as_error():
    status = build_running_aikido_sync_status(
        "source-1",
        message="Sync running.",
        started_at="2026-05-23T12:00:00Z",
    )
    stale_updated_at = datetime.now(timezone.utc) - timedelta(minutes=31)

    coerced = coerce_stale_running_status(
        status,
        updated_at=stale_updated_at,
        stale_after_seconds=30 * 60,
    )

    assert coerced["status"] == "error"
    assert "stalled" in coerced["message"].lower()
    assert coerced["step"] == 0
    assert coerced["total"] == AIKIDO_FULL_SYNC_TOTAL_STEPS
