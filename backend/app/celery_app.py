"""Celery application for VAT sync worker."""

import logging

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

# Suppress httpx HTTP request logs unless VAT_LOG_HTTP_REQUESTS=true (avoids Linear/Aikido API flood)
logging.getLogger("httpx").setLevel(
    logging.DEBUG if settings.log_http_requests else logging.WARNING
)

app = Celery(
    "vat",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend or settings.celery_broker_url,
    include=["app.tasks.sync_tasks"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,  # Re-queue if worker crashes mid-task
    worker_prefetch_multiplier=1,  # One task at a time per worker (avoid long queue starvation)
)

# Beat schedule: process sync queue every 2 minutes; Linear poll when enabled; reconciliation as safety net
_poll_interval = get_settings().linear_poll_interval_min * 60
# When webhook configured, poll task no-ops. Reconciliation runs regardless to catch missed webhooks.
_reconcile_hours = get_settings().linear_reconcile_interval_hours
_reconcile_interval = max(1, _reconcile_hours) * 60 * 60
_process_limit = get_settings().linear_sync_process_limit
_backfill_limit = get_settings().linear_sync_backfill_limit
app.conf.beat_schedule = {
    "process-sync-queue": {
        "task": "app.tasks.sync_tasks.process_sync_queue",
        "schedule": 120.0,  # seconds
        "options": {"queue": "vat-sync"},
        "kwargs": {"limit": _process_limit, "backfill_limit": _backfill_limit},
    },
    "poll-linear": {
        "task": "app.tasks.sync_tasks.poll_linear",
        "schedule": float(_poll_interval),
        "options": {"queue": "vat-sync"},
    },
    "reconcile-linear": {
        "task": "app.tasks.sync_tasks.reconcile_linear",
        "schedule": float(_reconcile_interval),
        "options": {"queue": "vat-sync"},
    },
}

app.conf.task_default_queue = "vat-sync"
app.conf.task_routes = {"app.tasks.sync_tasks.*": {"queue": "vat-sync"}}
