from __future__ import annotations

from app.services import observability


def test_observability_counters_and_http_recording_render():
    state = observability._ObservabilityState()

    state.inc_audit_event('evt "x"\\path')
    state.inc_audit_emit_failure()
    state.inc_audit_otel_mirror()
    state.inc_audit_otel_mirror_failure()
    state.record_ingest_latency(0.2)
    state.record_http_request(
        route='/v1/assets/"quoted"\\path',
        method="get",
        status_code=200,
        duration_seconds=0.2,
        response_bytes=-11,  # clamped at zero
    )
    state.record_http_request(
        route="/v1/assets",
        method="POST",
        status_code=500,
        duration_seconds=12.0,
        response_bytes=42,
    )

    output = state.render_prometheus()

    assert "vat_audit_events_total 1" in output
    assert 'vat_audit_events_by_type_total{event_type="evt \\"x\\"\\\\path"} 1' in output
    assert "vat_audit_emit_failures_total 1" in output
    assert "vat_audit_otel_mirror_total 1" in output
    assert "vat_audit_otel_mirror_failures_total 1" in output
    assert "vat_ingest_requests_total 1" in output
    assert "vat_ingest_latency_seconds_sum 0.2" in output
    assert "vat_ingest_latency_seconds_count 1" in output
    assert (
        'vat_http_requests_total{route="/v1/assets/\\"quoted\\"\\\\path",method="GET",status="200"} 1'
        in output
    )
    # One value below many buckets and one value above all fixed buckets.
    assert (
        'vat_http_request_latency_seconds_bucket{route="/v1/assets/\\"quoted\\"\\\\path",method="GET",status="200",le="+Inf"} 1'
        in output
    )
    assert (
        'vat_http_request_latency_seconds_bucket{route="/v1/assets",method="POST",status="500",le="+Inf"} 1'
        in output
    )
    assert (
        'vat_http_response_bytes_total{route="/v1/assets/\\"quoted\\"\\\\path",method="GET",status="200"} 0'
        in output
    )
    assert (
        'vat_http_response_bytes_total{route="/v1/assets",method="POST",status="500"} 42'
        in output
    )


def test_ingest_latency_timer_records_non_negative(monkeypatch):
    fake_metrics = observability._ObservabilityState()
    monkeypatch.setattr(observability, "METRICS", fake_metrics)

    times = iter([10.0, 9.0])  # negative elapsed path -> clamped to 0.0
    monkeypatch.setattr(observability, "perf_counter", lambda: next(times))

    with observability.IngestLatencyTimer():
        pass

    assert fake_metrics.ingest_requests_total == 1
    assert fake_metrics.ingest_latency_seconds_count == 1
    assert fake_metrics.ingest_latency_seconds_sum == 0.0
