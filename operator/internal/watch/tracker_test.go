package watch

import (
	"strings"
	"testing"
)

func TestTrackerDedupsByDigestAndWarmSet(t *testing.T) {
	known := "sha256:" + strings.Repeat("a", 64)
	tr := NewTracker([]string{known})

	a := WorkItem{ImageRef: "x:1", Digest: known}                               // already warm -> not fresh
	b := WorkItem{ImageRef: "y:1", Digest: "sha256:" + strings.Repeat("b", 64)} // new digest -> fresh once

	fresh := tr.Observe([]WorkItem{a, b, b})
	if len(fresh) != 1 || fresh[0].Digest != b.Digest {
		t.Fatalf("want only b fresh once, got %+v", fresh)
	}
	if again := tr.Observe([]WorkItem{b}); len(again) != 0 {
		t.Fatalf("b should now be deduped, got %+v", again)
	}
}

func TestTrackerFallsBackToImageRefWhenDigestUnknown(t *testing.T) {
	tr := NewTracker(nil)
	noDigest := WorkItem{ImageRef: "repo/app:latest"}

	if fresh := tr.Observe([]WorkItem{noDigest}); len(fresh) != 1 {
		t.Fatalf("first sighting of digest-less ref should be fresh, got %+v", fresh)
	}
	if again := tr.Observe([]WorkItem{noDigest}); len(again) != 0 {
		t.Fatalf("same digest-less ref should dedup by imageRef, got %+v", again)
	}
}
