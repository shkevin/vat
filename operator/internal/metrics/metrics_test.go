package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderExposesCountersInPromFormat(t *testing.T) {
	IncCreated("event")
	IncCreated("backstop")
	AddCreatedBackstop(2)
	AddDedupHits(5)
	AddGCDeleted(1)
	SetBacklog(3)

	rec := httptest.NewRecorder()
	Render(rec)
	body := rec.Body.String()

	for _, want := range []string{
		"vat_scanrequests_created_total{trigger=\"event\"} 1",
		"vat_scanrequests_created_total{trigger=\"backstop\"} 3", // 1 + 2
		"vat_scan_dedup_hits_total 5",
		"vat_scanrequest_gc_deleted_total 1",
		"vat_scanrequest_backlog 3",
		"# TYPE vat_scanrequest_backlog gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}
