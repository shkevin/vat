"""Minimal Prometheus-style in-process metrics for VAT."""

from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import perf_counter


class _ObservabilityState:
    def __init__(self) -> None:
        self._lock = Lock()
        self.audit_events_total = 0
        self.audit_events_by_type: dict[str, int] = defaultdict(int)
        self.audit_emit_failures_total = 0
        self.audit_otel_mirror_total = 0
        self.audit_otel_mirror_failures_total = 0
        self.ingest_requests_total = 0
        self.ingest_latency_seconds_sum = 0.0
        self.ingest_latency_seconds_count = 0

    def inc_audit_event(self, event_type: str) -> None:
        with self._lock:
            self.audit_events_total += 1
            self.audit_events_by_type[event_type] += 1

    def inc_audit_emit_failure(self) -> None:
        with self._lock:
            self.audit_emit_failures_total += 1

    def inc_audit_otel_mirror(self) -> None:
        with self._lock:
            self.audit_otel_mirror_total += 1

    def inc_audit_otel_mirror_failure(self) -> None:
        with self._lock:
            self.audit_otel_mirror_failures_total += 1

    def record_ingest_latency(self, seconds: float) -> None:
        with self._lock:
            self.ingest_requests_total += 1
            self.ingest_latency_seconds_sum += seconds
            self.ingest_latency_seconds_count += 1

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP vat_audit_events_total Total number of audit events emitted.",
                "# TYPE vat_audit_events_total counter",
                f"vat_audit_events_total {self.audit_events_total}",
                "# HELP vat_audit_events_by_type_total Audit events by type.",
                "# TYPE vat_audit_events_by_type_total counter",
            ]
            for event_type, count in sorted(self.audit_events_by_type.items()):
                safe_type = event_type.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'vat_audit_events_by_type_total{{event_type="{safe_type}"}} {count}')
            lines.extend(
                [
                    "# HELP vat_audit_emit_failures_total Failed audit event emissions.",
                    "# TYPE vat_audit_emit_failures_total counter",
                    f"vat_audit_emit_failures_total {self.audit_emit_failures_total}",
                    "# HELP vat_audit_otel_mirror_total Audit events mirrored to OTEL.",
                    "# TYPE vat_audit_otel_mirror_total counter",
                    f"vat_audit_otel_mirror_total {self.audit_otel_mirror_total}",
                    "# HELP vat_audit_otel_mirror_failures_total Audit events that failed OTEL mirror.",
                    "# TYPE vat_audit_otel_mirror_failures_total counter",
                    f"vat_audit_otel_mirror_failures_total {self.audit_otel_mirror_failures_total}",
                    "# HELP vat_ingest_requests_total Total ingest requests processed.",
                    "# TYPE vat_ingest_requests_total counter",
                    f"vat_ingest_requests_total {self.ingest_requests_total}",
                    "# HELP vat_ingest_latency_seconds Ingest latency summary.",
                    "# TYPE vat_ingest_latency_seconds summary",
                    f"vat_ingest_latency_seconds_sum {self.ingest_latency_seconds_sum}",
                    f"vat_ingest_latency_seconds_count {self.ingest_latency_seconds_count}",
                ]
            )
            return "\n".join(lines) + "\n"


METRICS = _ObservabilityState()


class IngestLatencyTimer:
    """Simple context manager to record ingest latency metrics."""

    def __enter__(self) -> "IngestLatencyTimer":
        self._start = perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        METRICS.record_ingest_latency(max(0.0, perf_counter() - self._start))

