#!/usr/bin/env bash
set -euo pipefail

# Measure /api/vat-data latency with authenticated local traffic and report
# before/after Prometheus metric deltas for the same endpoint.
#
# Required auth (one of):
#   - VAT_TOKEN
#   - VAT_USER_EMAIL
#
# Optional env vars:
#   VAT_API_BASE            default: http://localhost:8000
#   VAT_ENDPOINT            default: /api/vat-data?page=1&page_size=100&include_assets=true&include_zero_assets=false
#   VAT_METRICS_ENDPOINT    default: /metrics
#   VAT_REQUESTS            default: 40
#   VAT_WARMUP              default: 5
#   VAT_SLEEP_SECONDS       default: 0.2
#   VAT_CURL_TIMEOUT        default: 20
#   VAT_REPORT_PATH         default: ./artifacts/vat-data-p95-report-<timestamp>.md

VAT_API_BASE="${VAT_API_BASE:-http://localhost:8000}"
VAT_ENDPOINT="${VAT_ENDPOINT:-/api/vat-data?page=1&page_size=100&include_assets=true&include_zero_assets=false}"
VAT_METRICS_ENDPOINT="${VAT_METRICS_ENDPOINT:-/metrics}"
VAT_REQUESTS="${VAT_REQUESTS:-40}"
VAT_WARMUP="${VAT_WARMUP:-5}"
VAT_SLEEP_SECONDS="${VAT_SLEEP_SECONDS:-0.2}"
VAT_CURL_TIMEOUT="${VAT_CURL_TIMEOUT:-20}"

if [[ -z "${VAT_TOKEN:-}" && -z "${VAT_USER_EMAIL:-}" ]]; then
  echo "ERROR: set VAT_TOKEN or VAT_USER_EMAIL before running."
  exit 1
fi

if ! [[ "${VAT_REQUESTS}" =~ ^[0-9]+$ ]] || ! [[ "${VAT_WARMUP}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: VAT_REQUESTS and VAT_WARMUP must be integers."
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
default_report_path="/home/shkevin/code/compliance/vat/artifacts/vat-data-p95-report-${timestamp}.md"
VAT_REPORT_PATH="${VAT_REPORT_PATH:-${default_report_path}}"

report_dir="$(dirname "${VAT_REPORT_PATH}")"
mkdir -p "${report_dir}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

latency_ms_file="${tmp_dir}/latency_ms.txt"
status_file="${tmp_dir}/status_codes.txt"
metrics_before_file="${tmp_dir}/metrics_before.txt"
metrics_after_file="${tmp_dir}/metrics_after.txt"

declare -a headers=()
if [[ -n "${VAT_TOKEN:-}" ]]; then
  headers+=(-H "Authorization: Bearer ${VAT_TOKEN}")
elif [[ -n "${VAT_USER_EMAIL:-}" ]]; then
  headers+=(-H "X-VAT-User: ${VAT_USER_EMAIL}")
fi

fetch_metrics() {
  local out_file="$1"
  if ! curl -sS --max-time "${VAT_CURL_TIMEOUT}" "${VAT_API_BASE}${VAT_METRICS_ENDPOINT}" > "${out_file}"; then
    echo "WARN: unable to fetch ${VAT_METRICS_ENDPOINT}; metrics diff will be empty."
    : > "${out_file}"
  fi
}

run_request() {
  local response_meta
  response_meta="$(curl -sS -o /dev/null \
    --max-time "${VAT_CURL_TIMEOUT}" \
    "${headers[@]}" \
    -w "%{http_code} %{time_total} %{size_download}" \
    "${VAT_API_BASE}${VAT_ENDPOINT}")"

  local http_code time_total size_download
  http_code="$(awk '{print $1}' <<< "${response_meta}")"
  time_total="$(awk '{print $2}' <<< "${response_meta}")"
  size_download="$(awk '{print $3}' <<< "${response_meta}")"

  echo "${http_code}" >> "${status_file}"

  python - "${time_total}" "${size_download}" <<'PY'
import sys
time_total = float(sys.argv[1])
size_download = int(float(sys.argv[2]))
latency_ms = time_total * 1000.0
print(f"{latency_ms:.3f} {size_download}")
PY
}

echo "Collecting pre-run metrics from ${VAT_API_BASE}${VAT_METRICS_ENDPOINT}..."
fetch_metrics "${metrics_before_file}"

total_runs="$((VAT_WARMUP + VAT_REQUESTS))"
echo "Running ${total_runs} requests (${VAT_WARMUP} warmup + ${VAT_REQUESTS} measured) against:"
echo "  ${VAT_API_BASE}${VAT_ENDPOINT}"

success_count=0
failure_count=0
measured_count=0

for ((i=1; i<=total_runs; i++)); do
  req_output="$(run_request)"
  http_code="$(tail -n 1 "${status_file}")"
  latency_ms="$(awk '{print $1}' <<< "${req_output}")"
  response_bytes="$(awk '{print $2}' <<< "${req_output}")"

  if [[ "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
    ((success_count+=1))
  else
    ((failure_count+=1))
  fi

  if (( i > VAT_WARMUP )); then
    ((measured_count+=1))
    echo "${latency_ms} ${response_bytes} ${http_code}" >> "${latency_ms_file}"
  fi

  sleep "${VAT_SLEEP_SECONDS}"
done

echo "Collecting post-run metrics from ${VAT_API_BASE}${VAT_METRICS_ENDPOINT}..."
fetch_metrics "${metrics_after_file}"

python - "${latency_ms_file}" "${metrics_before_file}" "${metrics_after_file}" "${VAT_REPORT_PATH}" "${VAT_API_BASE}${VAT_ENDPOINT}" "${success_count}" "${failure_count}" "${measured_count}" <<'PY'
import re
import statistics
import sys
from pathlib import Path

lat_file = Path(sys.argv[1])
metrics_before_file = Path(sys.argv[2])
metrics_after_file = Path(sys.argv[3])
report_path = Path(sys.argv[4])
target_url = sys.argv[5]
success_count = int(sys.argv[6])
failure_count = int(sys.argv[7])
measured_count = int(sys.argv[8])

rows = []
for line in lat_file.read_text().strip().splitlines():
    if not line.strip():
        continue
    ms, size_bytes, code = line.split()
    rows.append((float(ms), int(size_bytes), code))

latencies = [r[0] for r in rows if r[2].startswith("2")]
sizes = [r[1] for r in rows if r[2].startswith("2")]

def percentile(vals, p):
    if not vals:
        return None
    vals_sorted = sorted(vals)
    if len(vals_sorted) == 1:
        return vals_sorted[0]
    rank = (len(vals_sorted) - 1) * p
    low = int(rank)
    high = min(low + 1, len(vals_sorted) - 1)
    frac = rank - low
    return vals_sorted[low] * (1 - frac) + vals_sorted[high] * frac

def fmt_float(v):
    return "n/a" if v is None else f"{v:.2f}"

def parse_metrics(text):
    metric_map = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " " not in line:
            continue
        name_and_labels, value_str = line.rsplit(" ", 1)
        try:
            value = float(value_str)
        except ValueError:
            continue
        metric_map[name_and_labels] = value
    return metric_map

before = parse_metrics(metrics_before_file.read_text() if metrics_before_file.exists() else "")
after = parse_metrics(metrics_after_file.read_text() if metrics_after_file.exists() else "")

route_fragment = 'route="/api/vat-data"'
interesting_prefixes = (
    "vat_http_requests_total{",
    "vat_http_request_latency_seconds_sum{",
    "vat_http_request_latency_seconds_count{",
    "vat_http_request_latency_seconds_bucket{",
    "vat_http_response_bytes_total{",
)
interesting_keys = sorted(
    {
        k
        for k in set(before) | set(after)
        if route_fragment in k and k.startswith(interesting_prefixes)
    }
)

metric_lines = []
for k in interesting_keys:
    b = before.get(k, 0.0)
    a = after.get(k, 0.0)
    d = a - b
    metric_lines.append((k, b, a, d))

p50 = percentile(latencies, 0.50)
p90 = percentile(latencies, 0.90)
p95 = percentile(latencies, 0.95)
p99 = percentile(latencies, 0.99)
avg = statistics.mean(latencies) if latencies else None
size_avg = statistics.mean(sizes) if sizes else None
size_p95 = percentile(sizes, 0.95) if sizes else None

with report_path.open("w", encoding="utf-8") as f:
    f.write("# VAT /api/vat-data local latency report\n\n")
    f.write(f"- Target URL: `{target_url}`\n")
    f.write(f"- Measured requests: `{measured_count}`\n")
    f.write(f"- Successful responses (2xx): `{success_count}`\n")
    f.write(f"- Failed responses (non-2xx): `{failure_count}`\n\n")

    f.write("## Client-observed latency (curl time_total)\n\n")
    f.write("| Metric | Value |\n")
    f.write("|---|---:|\n")
    f.write(f"| avg_ms | {fmt_float(avg)} |\n")
    f.write(f"| p50_ms | {fmt_float(p50)} |\n")
    f.write(f"| p90_ms | {fmt_float(p90)} |\n")
    f.write(f"| p95_ms | {fmt_float(p95)} |\n")
    f.write(f"| p99_ms | {fmt_float(p99)} |\n")
    f.write(f"| avg_response_bytes | {fmt_float(size_avg)} |\n")
    f.write(f"| p95_response_bytes | {fmt_float(size_p95)} |\n\n")

    f.write("## Prometheus metric deltas (/metrics before vs after)\n\n")
    f.write("| Metric | Before | After | Delta |\n")
    f.write("|---|---:|---:|---:|\n")
    for k, b, a, d in metric_lines:
        f.write(f"| `{k}` | {b:.6f} | {a:.6f} | {d:.6f} |\n")

print(f"Report written to: {report_path}")
if p95 is not None:
    print(f"p95 latency (ms): {p95:.2f}")
else:
    print("p95 latency (ms): n/a")
if not latencies:
    print("WARN: no successful (2xx) measured requests. Check auth headers and endpoint parameters.")
PY

echo "Done."
