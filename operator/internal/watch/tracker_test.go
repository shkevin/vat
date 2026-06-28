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

// The pod-Add (ref only) -> pod-Update (ref + resolved digest) transition for one
// container must produce a single fresh item, not two ScanRequests.
func TestTrackerCollapsesRefThenDigestForSameImage(t *testing.T) {
	tr := NewTracker(nil)
	digest := "sha256:" + strings.Repeat("c", 64)

	add := WorkItem{ImageRef: "busybox:1.37.0"}                    // Add: no digest yet
	update := WorkItem{ImageRef: "busybox:1.37.0", Digest: digest} // Update: digest resolved

	if fresh := tr.Observe([]WorkItem{add}); len(fresh) != 1 {
		t.Fatalf("ref-only Add should be fresh once, got %+v", fresh)
	}
	if again := tr.Observe([]WorkItem{update}); len(again) != 0 {
		t.Fatalf("same image with resolved digest must dedup (no second CR), got %+v", again)
	}
	// And a different pod sharing that digest via another tag still dedups on digest.
	other := WorkItem{ImageRef: "mirror/busybox:1.37.0", Digest: digest}
	if again := tr.Observe([]WorkItem{other}); len(again) != 0 {
		t.Fatalf("same digest via a different ref must dedup, got %+v", again)
	}
}
