// Package metrics exposes event-driven scan counters in Prometheus text format.
// Hand-rolled over net/http rather than pulling in prometheus/client_golang — the
// exposition format is just text and we only need counters + one gauge.
// ponytail: adopt client_golang if histograms/quantiles (e.g. scan latency) are needed.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

var (
	createdEvent    atomic.Int64
	createdBackstop atomic.Int64
	dedupHits       atomic.Int64
	gcDeleted       atomic.Int64
	backlog         atomic.Int64
)

// IncCreated records one ScanRequest creation by trigger ("event" | "backstop").
func IncCreated(trigger string) {
	if trigger == "backstop" {
		createdBackstop.Add(1)
		return
	}
	createdEvent.Add(1)
}

// AddCreatedBackstop records a batch of backstop-created ScanRequests.
func AddCreatedBackstop(n int) {
	if n > 0 {
		createdBackstop.Add(int64(n))
	}
}

// AddDedupHits records digests skipped as already-known.
func AddDedupHits(n int) {
	if n > 0 {
		dedupHits.Add(int64(n))
	}
}

// AddGCDeleted records garbage-collected finished ScanRequests.
func AddGCDeleted(n int) {
	if n > 0 {
		gcDeleted.Add(int64(n))
	}
}

// SetBacklog sets the pending-ScanRequest gauge (sampled each backstop tick).
func SetBacklog(n int) { backlog.Store(int64(n)) }

// Render writes the current metrics in Prometheus text exposition format.
func Render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprint(w, "# HELP vat_scanrequests_created_total ScanRequests created, by trigger.\n")
	fmt.Fprint(w, "# TYPE vat_scanrequests_created_total counter\n")
	fmt.Fprintf(w, "vat_scanrequests_created_total{trigger=\"event\"} %d\n", createdEvent.Load())
	fmt.Fprintf(w, "vat_scanrequests_created_total{trigger=\"backstop\"} %d\n", createdBackstop.Load())
	fmt.Fprint(w, "# HELP vat_scan_dedup_hits_total Digests skipped as already-known.\n")
	fmt.Fprint(w, "# TYPE vat_scan_dedup_hits_total counter\n")
	fmt.Fprintf(w, "vat_scan_dedup_hits_total %d\n", dedupHits.Load())
	fmt.Fprint(w, "# HELP vat_scanrequest_gc_deleted_total Finished ScanRequests garbage-collected.\n")
	fmt.Fprint(w, "# TYPE vat_scanrequest_gc_deleted_total counter\n")
	fmt.Fprintf(w, "vat_scanrequest_gc_deleted_total %d\n", gcDeleted.Load())
	fmt.Fprint(w, "# HELP vat_scanrequest_backlog Pending ScanRequests at the last backstop tick.\n")
	fmt.Fprint(w, "# TYPE vat_scanrequest_backlog gauge\n")
	fmt.Fprintf(w, "vat_scanrequest_backlog %d\n", backlog.Load())
}

// Serve starts the metrics/health HTTP server. Blocks; run in a goroutine.
func Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) { Render(w) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return http.ListenAndServe(addr, mux)
}
