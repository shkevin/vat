"""Tests for vulnerability feed Celery scheduling and dedupe helpers."""

from sqlalchemy import text

from app.celery_app import app as celery_app
from app.services.vuln_feeds import request_vuln_feed_refresh_enqueue


def test_vuln_feed_refresh_beat_task_expires():
    schedule = celery_app.conf.beat_schedule["refresh-vuln-feeds"]

    assert schedule["options"]["queue"] == "vat-feeds"
    assert schedule["options"]["expires"] > 0


async def test_vuln_feed_refresh_enqueue_marker_dedupes_active_refresh(db):
    await db.execute(text("DELETE FROM settings WHERE key = 'vuln_feed_refresh_status'"))

    first_accepted, first_status = await request_vuln_feed_refresh_enqueue(
        db, actor_id="admin@vat.local"
    )
    await db.commit()
    second_accepted, second_status = await request_vuln_feed_refresh_enqueue(
        db, actor_id="admin@vat.local"
    )

    assert first_accepted is True
    assert first_status["status"] == "queued"
    assert second_accepted is False
    assert second_status["status"] == "queued"
