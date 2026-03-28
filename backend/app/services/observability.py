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
        self.http_latency_buckets = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.http_requests_total: dict[tuple[str, str, int], int] = defaultdict(int)
        self.http_request_latency_seconds_sum: dict[tuple[str, str, int], float] = (
            defaultdict(float)
        )
        self.http_request_latency_seconds_count: dict[tuple[str, str, int], int] = (
            defaultdict(int)
        )
        self.http_request_latency_bucket_count: dict[tuple[str, str, int, str], int] = (
            defaultdict(int)
        )
        self.http_response_bytes_total: dict[tuple[str, str, int], int] = defaultdict(
            int
        )

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

    def record_http_request(
        self,
        *,
        route: str,
        method: str,
        status_code: int,
        duration_seconds: float,
        response_bytes: int,
    ) -> None:
        key = (route, method.upper(), status_code)
        with self._lock:
            self.http_requests_total[key] += 1
            self.http_request_latency_seconds_sum[key] += duration_seconds
            self.http_request_latency_seconds_count[key] += 1
            self.http_response_bytes_total[key] += max(0, int(response_bytes))
            for bucket in self.http_latency_buckets:
                if duration_seconds <= bucket:
                    self.http_request_latency_bucket_count[
                        (route, method.upper(), status_code, str(bucket))
                    ] += 1
            self.http_request_latency_bucket_count[
                (route, method.upper(), status_code, "+Inf")
            ] += 1

    def render_prometheus(self) -> str:
        def _safe(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"')

        with self._lock:
            lines = [
                "# HELP vat_audit_events_total Total number of audit events emitted.",
                "# TYPE vat_audit_events_total counter",
                f"vat_audit_events_total {self.audit_events_total}",
                "# HELP vat_audit_events_by_type_total Audit events by type.",
                "# TYPE vat_audit_events_by_type_total counter",
            ]
            for event_type, count in sorted(self.audit_events_by_type.items()):
                safe_type = _safe(event_type)
                lines.append(
                    f'vat_audit_events_by_type_total{{event_type="{safe_type}"}} {count}'
                )
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
                    "# HELP vat_http_requests_total Total HTTP requests handled by route, method, and status.",
                    "# TYPE vat_http_requests_total counter",
                    "# HELP vat_http_request_latency_seconds HTTP request latency summary by route/method/status.",
                    "# TYPE vat_http_request_latency_seconds summary",
                    "# HELP vat_http_request_latency_seconds_bucket HTTP request latency histogram buckets by route/method/status.",
                    "# TYPE vat_http_request_latency_seconds_bucket counter",
                    "# HELP vat_http_response_bytes_total Total HTTP response bytes by route/method/status.",
                    "# TYPE vat_http_response_bytes_total counter",
                ]
            )
            for (route, method, status_code), count in sorted(
                self.http_requests_total.items()
            ):
                safe_route = _safe(route)
                lines.append(
                    f'vat_http_requests_total{{route="{safe_route}",method="{method}",status="{status_code}"}} {count}'
                )
            for (route, method, status_code), count in sorted(
                self.http_request_latency_seconds_count.items()
            ):
                safe_route = _safe(route)
                sum_val = self.http_request_latency_seconds_sum[
                    (route, method, status_code)
                ]
                lines.append(
                    f'vat_http_request_latency_seconds_sum{{route="{safe_route}",method="{method}",status="{status_code}"}} {sum_val}'
                )
                lines.append(
                    f'vat_http_request_latency_seconds_count{{route="{safe_route}",method="{method}",status="{status_code}"}} {count}'
                )
            for (route, method, status_code, bucket), count in sorted(
                self.http_request_latency_bucket_count.items()
            ):
                safe_route = _safe(route)
                lines.append(
                    f'vat_http_request_latency_seconds_bucket{{route="{safe_route}",method="{method}",status="{status_code}",le="{bucket}"}} {count}'
                )
            for (route, method, status_code), total_bytes in sorted(
                self.http_response_bytes_total.items()
            ):
                safe_route = _safe(route)
                lines.append(
                    f'vat_http_response_bytes_total{{route="{safe_route}",method="{method}",status="{status_code}"}} {total_bytes}'
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
