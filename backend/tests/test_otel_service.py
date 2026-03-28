from __future__ import annotations

import sys
from types import ModuleType
from types import SimpleNamespace

from app.services import otel


class _Span:
    def __init__(self):
        self.attrs = {}

    def set_attribute(self, k, v):
        self.attrs[k] = v


class _SpanCtx:
    def __init__(self, span):
        self._span = span

    def __enter__(self):
        return self._span

    def __exit__(self, exc_type, exc, tb):
        return False


def test_init_otel_disabled(monkeypatch):
    monkeypatch.setattr(
        otel,
        "get_settings",
        lambda: SimpleNamespace(otel_enabled=False),
    )
    otel.init_otel()
    assert otel._OTEL_ENABLED is False


def test_init_otel_enabled_success_with_fake_modules(monkeypatch):
    class _FakeTraceModule:
        def __init__(self):
            self.provider = None
            self.tracer = object()

        def set_tracer_provider(self, provider):
            self.provider = provider

        def get_tracer(self, _name):
            return self.tracer

    fake_trace = _FakeTraceModule()

    class _OTLPSpanExporter:
        def __init__(self, endpoint):
            self.endpoint = endpoint

    class _Resource:
        @staticmethod
        def create(payload):
            return payload

    class _TracerProvider:
        def __init__(self, resource):
            self.resource = resource
            self.processors = []

        def add_span_processor(self, proc):
            self.processors.append(proc)

    class _BatchSpanProcessor:
        def __init__(self, exporter):
            self.exporter = exporter

    m_root = ModuleType("opentelemetry")
    m_root.trace = fake_trace
    m_trace = ModuleType("opentelemetry.trace")
    m_exporter = ModuleType("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    m_exporter.OTLPSpanExporter = _OTLPSpanExporter
    m_resources = ModuleType("opentelemetry.sdk.resources")
    m_resources.Resource = _Resource
    m_sdk_trace = ModuleType("opentelemetry.sdk.trace")
    m_sdk_trace.TracerProvider = _TracerProvider
    m_sdk_trace_export = ModuleType("opentelemetry.sdk.trace.export")
    m_sdk_trace_export.BatchSpanProcessor = _BatchSpanProcessor

    monkeypatch.setitem(sys.modules, "opentelemetry", m_root)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", m_trace)
    monkeypatch.setitem(
        sys.modules,
        "opentelemetry.exporter.otlp.proto.http.trace_exporter",
        m_exporter,
    )
    monkeypatch.setitem(sys.modules, "opentelemetry.sdk.resources", m_resources)
    monkeypatch.setitem(sys.modules, "opentelemetry.sdk.trace", m_sdk_trace)
    monkeypatch.setitem(sys.modules, "opentelemetry.sdk.trace.export", m_sdk_trace_export)

    monkeypatch.setattr(
        otel,
        "get_settings",
        lambda: SimpleNamespace(
            otel_enabled=True,
            otel_service_name="vat-api",
            otel_exporter_otlp_endpoint="http://otel:4318/v1/traces",
            env="test",
        ),
    )

    otel.init_otel()
    assert otel._OTEL_ENABLED is True
    assert otel._TRACER is fake_trace.tracer


def test_mirror_audit_event_paths(monkeypatch):
    otel._OTEL_ENABLED = False
    otel._TRACER = None
    assert (
        otel.mirror_audit_event_to_otel(
            event_id="e",
            trace_id="t",
            event_type="x",
            source_id=None,
            parser_id=None,
            asset_id=None,
            finding_id=None,
            decision_name=None,
            decision_reason_code=None,
            decision_confidence=None,
            decision_result=None,
        )
        is False
    )

    span = _Span()
    tracer = SimpleNamespace(start_as_current_span=lambda _name: _SpanCtx(span))
    otel._OTEL_ENABLED = True
    otel._TRACER = tracer

    ok = otel.mirror_audit_event_to_otel(
        event_id="e1",
        trace_id="t1",
        event_type="decision",
        source_id="s1",
        parser_id="p1",
        asset_id="a1",
        finding_id="f1",
        decision_name="allow",
        decision_reason_code="R1",
        decision_confidence="high",
        decision_result="approved",
    )
    assert ok is True
    assert span.attrs["vat.audit.event_id"] == "e1"
    assert span.attrs["vat.audit.trace_id"] == "t1"
    assert span.attrs["vat.audit.decision_result"] == "approved"

    class _BadTracer:
        def start_as_current_span(self, _name):
            raise RuntimeError("boom")

    otel._TRACER = _BadTracer()
    assert (
        otel.mirror_audit_event_to_otel(
            event_id="e2",
            trace_id="t2",
            event_type="decision",
            source_id=None,
            parser_id=None,
            asset_id=None,
            finding_id=None,
            decision_name=None,
            decision_reason_code=None,
            decision_confidence=None,
            decision_result=None,
        )
        is False
    )
