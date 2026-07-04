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

	fresh := tr.Observe("pod-1", []WorkItem{a, b, b})
	if len(fresh) != 1 || fresh[0].Digest != b.Digest {
		t.Fatalf("want only b fresh once, got %+v", fresh)
	}
	if again := tr.Observe("pod-2", []WorkItem{b}); len(again) != 0 {
		t.Fatalf("b should now be deduped, got %+v", again)
	}
}

func TestTrackerFallsBackToImageRefWhenDigestUnknown(t *testing.T) {
	tr := NewTracker(nil)
	noDigest := WorkItem{ImageRef: "repo/app:latest"}

	if fresh := tr.Observe("pod-1", []WorkItem{noDigest}); len(fresh) != 1 {
		t.Fatalf("first sighting of digest-less ref should be fresh, got %+v", fresh)
	}
	if again := tr.Observe("pod-1", []WorkItem{noDigest}); len(again) != 0 {
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

	if fresh := tr.Observe("pod-1", []WorkItem{add}); len(fresh) != 1 {
		t.Fatalf("ref-only Add should be fresh once, got %+v", fresh)
	}
	if again := tr.Observe("pod-1", []WorkItem{update}); len(again) != 0 {
		t.Fatalf("same image with resolved digest must dedup (no second CR), got %+v", again)
	}
	// And a different pod sharing that digest via another tag still dedups on digest.
	other := WorkItem{ImageRef: "mirror/busybox:1.37.0", Digest: digest}
	if again := tr.Observe("pod-2", []WorkItem{other}); len(again) != 0 {
		t.Fatalf("same digest via a different ref must dedup, got %+v", again)
	}
}

// Deleting a pod must forget its image only when the LAST pod using it is gone,
// so a re-created image scans fresh but replica churn does not.
func TestTrackerForgetsImageWhenLastPodDeleted(t *testing.T) {
	tr := NewTracker(nil)
	digest := "sha256:" + strings.Repeat("d", 64)
	img := WorkItem{ImageRef: "repo/app:1", Digest: digest}

	// Two replicas of the same image: one scan, both pods reference the digest.
	if fresh := tr.Observe("pod-a", []WorkItem{img}); len(fresh) != 1 {
		t.Fatalf("first replica should be fresh, got %+v", fresh)
	}
	if fresh := tr.Observe("pod-b", []WorkItem{img}); len(fresh) != 0 {
		t.Fatalf("second replica must dedup, got %+v", fresh)
	}

	// Deleting one replica must NOT forget the image (pod-b still runs it).
	tr.Delete("pod-a")
	if fresh := tr.Observe("pod-c", []WorkItem{img}); len(fresh) != 0 {
		t.Fatalf("image still running on a replica must stay deduped, got %+v", fresh)
	}

	// Delete the remaining referencing pods; now the image is fully gone...
	tr.Delete("pod-b")
	tr.Delete("pod-c")

	// ...so a re-created identical image scans fresh again.
	if fresh := tr.Observe("pod-d", []WorkItem{img}); len(fresh) != 1 {
		t.Fatalf("re-created image after last pod deleted should scan fresh, got %+v", fresh)
	}
}

// Deleting an unknown/excluded pod (never observed) is a no-op, not a panic.
func TestTrackerDeleteUnknownPodIsNoop(t *testing.T) {
	tr := NewTracker([]string{"sha256:" + strings.Repeat("e", 64)})
	before := tr.Size()
	tr.Delete("never-seen")
	if tr.Size() != before {
		t.Fatalf("deleting unknown pod must not change tracked keys, size %d -> %d", before, tr.Size())
	}
}
