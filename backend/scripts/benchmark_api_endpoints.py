"""Simple API latency/payload baseline utility for VAT."""

from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass
from typing import Iterable

import httpx


@dataclass
class EndpointResult:
    name: str
    p50_ms: float
    p95_ms: float
    avg_ms: float
    bytes_avg: int
    samples: int


def _pct(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    idx = max(0, min(len(values) - 1, int(round((percentile / 100.0) * (len(values) - 1)))))
    return sorted(values)[idx]


def _bench_endpoint(
    client: httpx.Client,
    *,
    name: str,
    path: str,
    rounds: int,
) -> EndpointResult:
    durations: list[float] = []
    payload_sizes: list[int] = []
    for _ in range(rounds):
        start = time.perf_counter()
        resp = client.get(path)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        resp.raise_for_status()
        durations.append(elapsed_ms)
        payload_sizes.append(len(resp.content))
    return EndpointResult(
        name=name,
        p50_ms=round(_pct(durations, 50), 2),
        p95_ms=round(_pct(durations, 95), 2),
        avg_ms=round(statistics.fmean(durations), 2),
        bytes_avg=int(statistics.fmean(payload_sizes)),
        samples=rounds,
    )


def _print_results(results: Iterable[EndpointResult]) -> None:
    rows = list(results)
    print("endpoint,p50_ms,p95_ms,avg_ms,bytes_avg,samples")
    for row in rows:
        print(
            f"{row.name},{row.p50_ms},{row.p95_ms},{row.avg_ms},{row.bytes_avg},{row.samples}"
        )
    print("\njson:")
    print(json.dumps([r.__dict__ for r in rows], indent=2))


def main() -> None:
    api_base = (os.getenv("API_BASE") or "http://localhost:8000/api").rstrip("/")
    token = os.getenv("AUTH_TOKEN")
    rounds = int(os.getenv("ROUNDS") or "8")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    with httpx.Client(base_url=api_base, headers=headers, timeout=60.0) as client:
        results = [
            _bench_endpoint(
                client,
                name="vat_data",
                path="/vat-data?include_assets=true&include_zero_assets=true&page_size=500",
                rounds=rounds,
            ),
            _bench_endpoint(
                client,
                name="findings",
                path="/findings?limit=500",
                rounds=rounds,
            ),
            _bench_endpoint(
                client,
                name="finding_groups",
                path="/findings/groups?limit=100&offset=0",
                rounds=rounds,
            ),
        ]
    _print_results(results)


if __name__ == "__main__":
    main()
