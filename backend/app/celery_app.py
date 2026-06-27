"""Celery application for VAT sync worker."""

import logging
import os
import random

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings


def _jitter(base_seconds: float, frac: float = 0.05) -> float:
    """Apply a small ±frac (default ±5%) perturbation to an interval at boot.

    Celery's interval scheduler has no per-tick jitter, so multiple Beat
    replicas (or repeated reboots) all sync on the same minute boundary
    and stampede the same task at the same instant. Jittering the base
    interval per process lets the schedules drift apart naturally without
    a custom scheduler. NOTE: multi-replica Beat still needs
    RedBeat / k8s leader election for true singleton semantics; this only
    softens accidental alignment.
    """
    # Seed per-process so repeated calls within one boot return the same
    # offset (so tests / introspection see a stable value), but different
    # processes drift apart.
    rng = random.Random(os.getpid())
    return base_seconds * (1.0 + rng.uniform(-frac, frac))

settings = get_settings()

# Suppress httpx HTTP request logs unless VAT_LOG_HTTP_REQUESTS=true (avoids Linear/Aikido API flood)
logging.getLogger("httpx").setLevel(
    logging.DEBUG if settings.log_http_requests else logging.WARNING
)

app = Celery(
    "vat",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend or settings.celery_broker_url,
    include=[
        "app.tasks.aikido_tasks",
        "app.tasks.sync_tasks",
        "app.tasks.audit_tasks",
        "app.tasks.vuln_feed_tasks",
        "app.tasks.maintenance_tasks",
    ],
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
_vuln_feed_interval_hours = max(1, get_settings().vuln_feed_refresh_interval_hours)
_vuln_feed_task_expires_seconds = max(60, get_settings().vuln_feed_task_expires_seconds)
app.conf.beat_schedule = {
    "process-sync-queue": {
        "task": "app.tasks.sync_tasks.process_sync_queue",
        "schedule": _jitter(120.0),
        "options": {"queue": "vat-sync"},
        "kwargs": {"limit": _process_limit, "backfill_limit": _backfill_limit},
    },
    "poll-linear": {
        "task": "app.tasks.sync_tasks.poll_linear",
        "schedule": _jitter(float(_poll_interval)),
        "options": {"queue": "vat-sync"},
    },
    "reconcile-linear": {
        "task": "app.tasks.sync_tasks.reconcile_linear",
        "schedule": _jitter(float(_reconcile_interval)),
        "options": {"queue": "vat-sync"},
    },
    # Previous UTC day anchor (00:30 UTC); disable via VAT_AUDIT_DAILY_CHECKPOINT_ENABLED=false
    "audit-daily-checkpoint": {
        "task": "app.tasks.audit_tasks.run_daily_audit_checkpoint",
        "schedule": crontab(hour=0, minute=30),
        "options": {"queue": "vat-sync"},
    },
    "refresh-vuln-feeds": {
        "task": "app.tasks.vuln_feed_tasks.run_vuln_feed_refresh",
        "schedule": crontab(minute=0, hour=f"*/{_vuln_feed_interval_hours}"),
        "options": {"queue": "vat-feeds", "expires": _vuln_feed_task_expires_seconds},
    },
    "retain-vuln-feed-history": {
        "task": "app.tasks.vuln_feed_tasks.run_vuln_feed_retention",
        "schedule": crontab(hour=2, minute=15),
        "options": {"queue": "vat-feeds"},
    },
    "enforce-waiver-expiry": {
        "task": "app.tasks.maintenance_tasks.enforce_waiver_expiry_task",
        "schedule": crontab(hour=1, minute=0),
        "options": {"queue": "vat-maintenance"},
    },
}

app.conf.task_default_queue = "vat-sync"
app.conf.task_routes = {
    "app.tasks.aikido_tasks.*": {"queue": "vat-sync"},
    "app.tasks.sync_tasks.*": {"queue": "vat-sync"},
    "app.tasks.audit_tasks.*": {"queue": "vat-maintenance"},
    "app.tasks.maintenance_tasks.*": {"queue": "vat-maintenance"},
    "app.tasks.vuln_feed_tasks.*": {"queue": "vat-feeds"},
}
