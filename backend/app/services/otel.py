"""OpenTelemetry initialization and audit event mirroring helpers."""

from __future__ import annotations

import logging
from typing import Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_TRACER = None
_OTEL_ENABLED = False


def init_otel() -> None:
    """Initialize OTEL tracing if enabled and dependencies are available."""
    global _TRACER, _OTEL_ENABLED
    s = get_settings()
    if not getattr(s, "otel_enabled", False):
        _OTEL_ENABLED = False
        logger.info("OTEL disabled")
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": s.otel_service_name,
                "service.version": "0.1.0",
                "deployment.environment": s.env,
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=s.otel_exporter_otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _TRACER = trace.get_tracer("vat.audit")
        _OTEL_ENABLED = True
        logger.info(
            "OTEL enabled service=%s endpoint=%s",
            s.otel_service_name,
            s.otel_exporter_otlp_endpoint,
        )
    except Exception as exc:
        _TRACER = None
        _OTEL_ENABLED = False
        logger.warning("OTEL initialization failed; continuing without OTEL: %s", exc)


def mirror_audit_event_to_otel(
    *,
    event_id: str,
    trace_id: str,
    event_type: str,
    source_id: Optional[str],
    parser_id: Optional[str],
    asset_id: Optional[str],
    finding_id: Optional[str],
    decision_name: Optional[str],
    decision_reason_code: Optional[str],
    decision_confidence: Optional[str],
    decision_result: Optional[str],
) -> bool:
    """Best-effort OTEL mirror for already-authored audit ledger events."""
    if not _OTEL_ENABLED or _TRACER is None:
        return False
    try:
        with _TRACER.start_as_current_span("audit.event") as span:
            span.set_attribute("vat.audit.event_id", event_id)
            span.set_attribute("vat.audit.trace_id", trace_id)
            span.set_attribute("vat.audit.event_type", event_type)
            if source_id:
                span.set_attribute("vat.audit.source_id", source_id)
            if parser_id:
                span.set_attribute("vat.audit.parser_id", parser_id)
            if asset_id:
                span.set_attribute("vat.audit.asset_id", asset_id)
            if finding_id:
                span.set_attribute("vat.audit.finding_id", finding_id)
            if decision_name:
                span.set_attribute("vat.audit.decision_name", decision_name)
            if decision_reason_code:
                span.set_attribute("vat.audit.decision_reason_code", decision_reason_code)
            if decision_confidence:
                span.set_attribute("vat.audit.decision_confidence", decision_confidence)
            if decision_result:
                span.set_attribute("vat.audit.decision_result", decision_result)
        return True
    except Exception:
        return False

