"""VAT FastAPI application entry point."""

import logging
import uuid
from contextlib import asynccontextmanager
from time import perf_counter

from app.core.config import get_settings

# Suppress httpx HTTP request logs unless VAT_LOG_HTTP_REQUESTS=true
logging.getLogger("httpx").setLevel(
    logging.DEBUG if get_settings().log_http_requests else logging.WARNING
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from app.core.log_context import LogContextFilter, set_trace_id
from app.core.pii_filter import PIIFilter

# Apply PII redaction + per-request context (trace_id/tenant_id/user_id)
# to app logs (PRD §7.3). Also attach to "uvicorn" and root so access logs
# emitted by the server pick up trace_id when the middleware has run.
_log_context_filter = LogContextFilter()
for _logger_name in ("app", "uvicorn", "uvicorn.access", ""):
    _lgr = logging.getLogger(_logger_name)
    _lgr.addFilter(PIIFilter() if _logger_name == "app" else logging.Filter())
    _lgr.addFilter(_log_context_filter)
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    audit,
    aikido,
    assets,
    auth,
    client_config,
    decisions,
    export,
    findings,
    health,
    ingest,
    loadouts,
    oauth,
    sbom,
    scan,
    seed,
    settings,
    sync_worker,
    tenants,
    users,
    vat_data,
    vuln_feeds,
)
from app.api.webhooks import router as webhooks_router
from app.services.otel import init_otel
from app.services.observability import METRICS


_BACKEND_CSP_DIRECTIVES = (
    # API responses are usually JSON; the strict policy here serves the
    # error pages FastAPI emits and any future static assets bound to the
    # backend origin. No unsafe-eval anywhere — even on the API surface.
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = _BACKEND_CSP_DIRECTIVES
        if get_settings().env == "production":
            # HSTS: pin browsers to HTTPS for a year. Skipped in dev so a
            # self-signed/HTTP localhost setup doesn't get hard-pinned.
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        trace_id = getattr(request.state, "trace_id", None)
        if trace_id:
            response.headers["X-Trace-Id"] = trace_id
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit CSRF protection for cookie-authenticated requests.

    Browsers attach the httpOnly vat-session cookie automatically on
    cross-site form submits; SameSite=Lax already blocks most CSRF, but
    a same-site malicious script (e.g. compromised subdomain) could
    still ride the cookie. The fix: require an X-VAT-CSRF header on
    state-changing requests whose value matches the non-httpOnly
    vat-csrf cookie. An attacker on another origin cannot read the
    cookie (Lax + same-origin), so they cannot forge the header.

    Skipped when:
      - method is GET/HEAD/OPTIONS (no state change)
      - request carries Authorization: Bearer (non-browser caller —
        ingest, admin keys, machine-to-machine — those are not
        susceptible to cookie-confused-deputy)
      - path is in ``CSRF_EXEMPT_PREFIXES`` (ingest / webhook / oauth
        token endpoints meant for non-browser clients)
    """

    CSRF_EXEMPT_PREFIXES = (
        "/api/ingest",
        "/api/sbom/import",
        "/api/oauth/token",
        "/api/auth/login",  # bootstrap — no cookie yet
        "/api/auth/exchange-code",  # bootstrap — no cookie yet
        "/api/auth/google/",  # OAuth redirect flow
        "/webhook/",
        "/health",
    )

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        # Authorization header → non-browser caller, skip CSRF.
        if request.headers.get("authorization"):
            return await call_next(request)
        path = request.url.path
        if any(path.startswith(p) for p in self.CSRF_EXEMPT_PREFIXES):
            return await call_next(request)
        # Only enforce when a session cookie is present (otherwise the
        # request is anonymous and downstream auth will reject it
        # anyway).
        session = request.cookies.get("vat-session")
        if not session:
            return await call_next(request)
        cookie_token = request.cookies.get("vat-csrf")
        header_token = request.headers.get("x-vat-csrf")
        if not cookie_token or not header_token or cookie_token != header_token:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or mismatch"},
            )
        return await call_next(request)


class TraceIdMiddleware(BaseHTTPMiddleware):
    """Attach request trace id for observability/audit correlation.

    Also publishes the trace id into the LogContext ContextVar so any
    log call on this request thread inherits it without explicit
    plumbing. Tenant/user id are filled in by the auth dependency when
    it resolves the UserContext.
    """

    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-Id") or uuid.uuid4().hex
        request.state.trace_id = trace_id
        set_trace_id(trace_id)
        return await call_next(request)


class RequestObservabilityMiddleware(BaseHTTPMiddleware):
    """Capture route-level latency and payload metrics for Prometheus."""

    async def dispatch(self, request: Request, call_next):
        start = perf_counter()
        response = await call_next(request)
        elapsed = max(0.0, perf_counter() - start)
        route_path = getattr(getattr(request, "scope", {}).get("route"), "path", None)
        route = route_path or request.url.path
        content_length = response.headers.get("content-length")
        try:
            response_bytes = int(content_length) if content_length is not None else 0
        except ValueError:
            response_bytes = 0
        METRICS.record_http_request(
            route=route,
            method=request.method,
            status_code=response.status_code,
            duration_seconds=elapsed,
            response_bytes=response_bytes,
        )
        return response


from app.services.waiver_expiry import enforce_waiver_expiry

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run waiver expiry enforcement on startup (PRD §5.5.2)."""
    init_otel()
    try:
        count = await enforce_waiver_expiry()
        if count > 0:
            logger.info("Waiver expiry: auto-reopened %d expired findings", count)
    except Exception as e:
        logger.warning("Waiver expiry check failed (non-fatal): %s", e)

    # Dev: auto-create scanner admin token file if missing (scanner needs it for env_file).
    # After DB reset (down -v), overwrite stale token so scanner can auth.
    try:
        from app.core.config import get_settings
        from pathlib import Path

        settings = get_settings()
        if settings.env == "development":
            from app.core.database import async_session
            from app.services.admin_keys import create_admin_key, list_admin_keys

            token_path = Path("/app/data/.vat-scanner-token")
            token_path.parent.mkdir(parents=True, exist_ok=True)
            async with async_session() as db:
                keys = await list_admin_keys(db)
                if not keys:
                    _key_id, full_key, key_prefix, _msg = await create_admin_key(
                        db, cross_tenant=True
                    )
                    token_path.write_text(f"VAT_ADMIN_TOKEN={full_key}\n")
                    token_path.chmod(0o600)  # Owner-only; scanner reads via mounted volume
                    logger.info(
                        "Dev: created scanner admin token (prefix %s) at data/.vat-scanner-token",
                        key_prefix,
                    )
    except Exception as e:
        logger.warning("Dev scanner token bootstrap failed (non-fatal): %s", e)
    # Process any stale 'processing' sync events (worker crash recovery)
    try:
        from app.core.database import async_session
        from app.services.sync_service import process_pending_sync_events
        from sqlalchemy import update
        from app.models.sync_event import SyncEvent

        async with async_session() as db:
            # Reset stale processing (worker crash) to pending for retry
            await db.execute(
                update(SyncEvent)
                .where(SyncEvent.status == "processing")
                .values(status="pending", next_retry_at=None)
            )
            await db.commit()
        async with async_session() as db:
            processed = await process_pending_sync_events(db, limit=20)
            if processed > 0:
                logger.info("Sync queue: processed %d events on startup", processed)
    except Exception as e:
        logger.warning("Sync queue startup check failed (non-fatal): %s", e)
    yield
    # Graceful shutdown — close pooled httpx clients so we don't leak
    # sockets when uvicorn signals SIGTERM. Best-effort: a missed close
    # is reclaimed by the OS, so we never block shutdown on these.
    try:
        from app.adapters.aikido import aclose_aikido_client
        from app.adapters.linear import aclose_linear_client

        await aclose_aikido_client()
        await aclose_linear_client()
    except Exception as e:
        logger.warning("HTTP client shutdown failed (non-fatal): %s", e)


app = FastAPI(
    lifespan=lifespan,
    title="VAT — Vulnerability Assessment Tracker",
    description="Authoritative source of record for vulnerability and security findings",
    version="0.1.0",
)

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all so uncaught exceptions never leak SQL fragments / file paths /
    upstream tokens to clients. Logs the full traceback server-side keyed by
    the request trace id; the client gets a generic 500 + the trace id so ops
    can correlate without the user needing to repro.
    """
    trace_id = getattr(request.state, "trace_id", None)
    logger = logging.getLogger("app.unhandled")
    logger.error(
        "Unhandled exception during %s %s (trace_id=%s)",
        request.method,
        request.url.path,
        trace_id,
        exc_info=exc,
    )
    body: dict[str, str] = {"detail": "internal error"}
    if trace_id:
        body["traceId"] = trace_id
    return JSONResponse(status_code=500, content=body)


app.add_middleware(TraceIdMiddleware)
app.add_middleware(RequestObservabilityMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware)
_cors_origins = [o.strip() for o in get_settings().cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(client_config.router, prefix="/api/config", tags=["client-config"])
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(decisions.router, prefix="/api/decisions", tags=["decisions"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(vat_data.router, prefix="/api/vat-data", tags=["vat-data"])
app.include_router(export.router, prefix="/api/export", tags=["export"])
app.include_router(sbom.router, prefix="/api/sbom", tags=["sbom"])
app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(seed.router, prefix="/api/seed", tags=["seed"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(tenants.router, prefix="/api/tenants", tags=["tenants"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(loadouts.router, prefix="/api/loadouts", tags=["loadouts"])
app.include_router(oauth.router, prefix="/api/oauth", tags=["oauth"])
app.include_router(webhooks_router, prefix="/webhook", tags=["webhooks"])
app.include_router(aikido.router, prefix="/api/aikido", tags=["aikido"])
app.include_router(sync_worker.router, prefix="/api/sync", tags=["sync"])
app.include_router(vuln_feeds.router, prefix="/api/vuln-feeds", tags=["vuln-feeds"])


@app.get("/metrics", tags=["observability"])
async def metrics():
    """Prometheus scrape endpoint."""
    return PlainTextResponse(
        content=METRICS.render_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
