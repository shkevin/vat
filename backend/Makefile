# VAT Backend Makefile

.PHONY: run worker beat worker-beat verify-correlation

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Celery worker (processes sync queue)
worker:
	celery -A app.celery_app worker -Q vat-sync -l info

# Celery Beat (schedules periodic sync every 2 min)
beat:
	celery -A app.celery_app beat -l info

# Combined worker + beat (dev only, single process)
worker-beat:
	celery -A app.celery_app worker -B -Q vat-sync -l info

# Correlation reversibility quality gate (migrations + tests + coverage thresholds)
verify-correlation:
	uv run python scripts/verify_correlation_reversibility.py
