"""Application configuration."""

import os
from functools import lru_cache
from typing import Optional

try:
    from pydantic import model_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _PYDANTIC_V2 = True
except Exception:  # pragma: no cover - compatibility for pydantic v1 test environments
    from pydantic import BaseSettings, root_validator

    _PYDANTIC_V2 = False

DEFAULT_SECRET = "change-me-in-production"


class Settings(BaseSettings):
    """VAT application settings."""

    if _PYDANTIC_V2:
        model_config = SettingsConfigDict(env_file=".env", env_prefix="VAT_")
    else:
        class Config:
            env_file = ".env"
            env_prefix = "VAT_"

    # Database
    database_url: str = "postgresql+asyncpg://vat:vat@localhost:5432/vat"

    # Environment: development | production. When production, fail startup if secret_key is default.
    env: str = "development"

    # Auth
    secret_key: str = DEFAULT_SECRET
    jwt_expire_hours: int = 24

    # Google OAuth (for tenants with auth_method=google)
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None

    # Public base URL for webhook registration (e.g. https://vat.example.com)
    public_url: str = "http://localhost:8000"
    # Frontend URL for OAuth redirects (default: same host, port 3000)
    frontend_url: Optional[str] = None

    # Webhook validation
    aikido_webhook_secret: Optional[str] = None
    linear_webhook_secret: Optional[str] = None

    # Aikido (bootstrap: GET /issues/export) — OAuth client credentials
    aikido_client_id: Optional[str] = None
    aikido_client_secret: Optional[str] = None
    aikido_region: str = "eu"
    # Override base URL for integration tests (e.g. http://wiremock:8080/aikido)
    aikido_base_url: Optional[str] = None
    # Rate limiting — Aikido allows ~20 calls/min. Throttle to avoid 429.
    aikido_rate_limit_per_min: int = 15
    aikido_request_gap_ms: int = 2500  # Min ms between requests
    # Export sync data to Excel for validation (data science / leadership reporting)
    aikido_export_excel_dir: Optional[str] = (
        None  # e.g. ./data/exports — when set, each sync writes aikido_sync_YYYY-MM-DD_HHMMSS.xlsx
    )

    # Tracker (Linear)
    linear_api_key: Optional[str] = None
    linear_team_id: Optional[str] = None  # Required for issue creation
    # Override GraphQL URL for integration tests (e.g. http://wiremock:8080/linear/graphql)
    linear_api_url: Optional[str] = None
    # Post canonical [VAT] format back to Linear after successful parse (reinforces expected structure)
    linear_post_canonical_on_parse: bool = True
    # Re-inject template when issue description no longer has parseable [VAT] block
    linear_reinject_on_removal: bool = True
    # API polling — use when webhooks aren't configured (same credentials as Linear settings)
    # Defaults to True when no webhook configured; False when webhook is configured (webhooks preferred)
    linear_poll_enabled: bool = True

    if _PYDANTIC_V2:
        @model_validator(mode="after")
        def default_poll_when_no_webhook(self) -> "Settings":
            # When webhook not configured: poll is the only way to get [VAT] updates — default True
            if not self.linear_webhook_secret and "VAT_LINEAR_POLL_ENABLED" not in os.environ:
                self.linear_poll_enabled = True
            # When webhook configured: webhooks are preferred; default False unless explicitly set
            elif self.linear_webhook_secret and "VAT_LINEAR_POLL_ENABLED" not in os.environ:
                self.linear_poll_enabled = False
            return self
    else:
        @root_validator
        def default_poll_when_no_webhook(cls, values):
            # When webhook not configured: poll is the only way to get [VAT] updates — default True
            if not values.get("linear_webhook_secret") and "VAT_LINEAR_POLL_ENABLED" not in os.environ:
                values["linear_poll_enabled"] = True
            # When webhook configured: webhooks are preferred; default False unless explicitly set
            elif values.get("linear_webhook_secret") and "VAT_LINEAR_POLL_ENABLED" not in os.environ:
                values["linear_poll_enabled"] = False
            return values
    linear_poll_interval_min: int = 5
    linear_poll_max_issues: int = 100
    # Reconciliation: fetch [VAT] updates via API to catch missed webhooks. Runs regardless of webhook config.
    linear_reconcile_interval_hours: int = 6
    # Link fallback: when True, match unlinked findings to existing Linear issues by title (risky: can cause false matches).
    # Default False — only group_key and CVE are used for deduplication.
    linear_link_title_fallback: bool = (
        False  # VAT_LINEAR_LINK_TITLE_FALLBACK=true to enable
    )
    # Sync queue: process/backfill limits per beat run. Increase for faster drain when backlog is large.
    linear_sync_process_limit: int = 200
    linear_sync_backfill_limit: int = 200

    # Tracker batch updates (generic — used by Linear, future Jira, etc.)
    # Reduces API calls when syncing many corrections; each adapter enforces its own limits
    tracker_update_batch_size: int = 15
    tracker_batch_delay_ms: int = 100
    # Batch create: Linear issueBatchCreate; max issues per batch (Linear may limit)
    tracker_create_batch_size: int = 15

    # Ingest API (push sources: Trivy, CI)
    require_ingest_auth: bool = False  # When True, ingest endpoints require API key
    ingest_api_key: Optional[str] = None  # Global fallback key (VAT_INGEST_API_KEY)

    # Celery (sync worker) — Valkey/Redis-compatible broker
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: Optional[str] = (
        None  # None = no result store; use redis://... for results
    )
    # Worker concurrency: number of parallel tasks per worker (default 4 for sync throughput)
    celery_worker_concurrency: int = 4

    # Security: X-VAT-User header allows impersonation — only enable for dev/testing
    allow_dev_headers: bool = False  # VAT_ALLOW_DEV_HEADERS=true for local dev only

    # Logging: show httpx HTTP request logs (Linear, Aikido, etc.). Default False to avoid log flood.
    log_http_requests: bool = False  # VAT_LOG_HTTP_REQUESTS=true for debug

    # OpenTelemetry (operational mirror; audit ledger remains source of truth)
    otel_enabled: bool = False
    otel_service_name: str = "vat-backend"
    otel_exporter_otlp_endpoint: str = "http://otel-collector:4318/v1/traces"

    # CORS: comma-separated origins (e.g. https://vat.example.com,https://app.vat.example.com)
    cors_origins: str = "http://localhost:3000"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.env == "production" and s.secret_key == DEFAULT_SECRET:
        raise ValueError(
            "VAT_SECRET_KEY must be set to a secure value in production. "
            'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return s
