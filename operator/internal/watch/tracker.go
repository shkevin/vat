package watch

import "sync"

// Tracker is the in-memory dedup set, warmed from the backend's known-digests on
// startup and maintained from informer events. Keys on the resolved digest,
// falling back to the image ref when the digest is not yet known.
//
// Each dedup key is reference-counted by the set of live pod UIDs that reference
// it, so deleting one replica of a many-replica image does NOT evict the key —
// the key is forgotten only when its LAST pod is gone. That makes a re-created
// image scan fresh again, while rolling updates and pod churn stay deduped.
type Tracker struct {
	mu      sync.Mutex
	known   map[string]struct{}        // dedup keys currently considered already-scanned
	refs    map[string]int             // dedup key -> number of live pods referencing it
	podKeys map[string]map[string]bool // pod UID -> set of keys it contributed
}

// NewTracker seeds the dedup set with already-known digests from the backend.
// Warm keys have no owning pod (refs 0); they stay known until a live pod adopts
// then loses them, so they are never spuriously evicted.
func NewTracker(warm []string) *Tracker {
	known := make(map[string]struct{}, len(warm))
	for _, d := range warm {
		if d != "" {
			known[d] = struct{}{}
		}
	}
	return &Tracker{
		known:   known,
		refs:    make(map[string]int),
		podKeys: make(map[string]map[string]bool),
	}
}

// keysFor returns every dedup key an item can be known by: the digest (when
// resolved) and the image ref. A pod is first seen on Add with no digest yet
// (ref only), then again on Update once the image pulls (digest + ref); keying
// on both — and deduping if EITHER is known — collapses that pair to one scan
// instead of creating a second, digest-keyed ScanRequest for the same image.
func keysFor(it WorkItem) []string {
	keys := make([]string, 0, 2)
	if it.Digest != "" {
		keys = append(keys, it.Digest)
	}
	keys = append(keys, "ref:"+it.ImageRef)
	return keys
}

// Observe returns the subset of items not seen before, marking them seen and
// recording that podUID references their keys. An item is a dedup hit if ANY of
// its keys (digest or ref) is already known; otherwise it's fresh. Re-observing
// the same pod (informer resync/Update) is idempotent — refcounts track distinct
// pods, not call count, so resync never inflates them.
func (t *Tracker) Observe(podUID string, items []WorkItem) []WorkItem {
	t.mu.Lock()
	defer t.mu.Unlock()

	old := t.podKeys[podUID] // keys this pod contributed on its last observation
	newSet := make(map[string]bool)
	var fresh []WorkItem
	for _, it := range items {
		ks := keysFor(it)
		seen := false
		for _, k := range ks {
			if _, ok := t.known[k]; ok {
				seen = true
				break
			}
		}
		if !seen {
			fresh = append(fresh, it)
		}
		for _, k := range ks {
			if newSet[k] {
				continue // already accounted for this key in this call
			}
			newSet[k] = true
			if !old[k] {
				t.refs[k]++ // a new pod (or key) references this image
			}
			t.known[k] = struct{}{} // mark inline so intra-call duplicates dedup
		}
	}

	// Keys the pod dropped since last time (rare: spec image changed) decrement.
	for k := range old {
		if !newSet[k] {
			t.release(k)
		}
	}
	t.podKeys[podUID] = newSet
	return fresh
}

// Delete drops all keys the pod contributed, evicting any that no live pod
// references anymore so the image scans fresh if it ever returns. No-op for an
// unknown/excluded pod. Handles informer DeletedFinalStateUnknown tombstones —
// the caller unwraps those to the pod UID before calling.
func (t *Tracker) Delete(podUID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keys, ok := t.podKeys[podUID]
	if !ok {
		return
	}
	delete(t.podKeys, podUID)
	for k := range keys {
		t.release(k)
	}
}

// release decrements a key's refcount and evicts it from the dedup set when the
// last pod referencing it is gone. Caller holds the lock.
func (t *Tracker) release(k string) {
	t.refs[k]--
	if t.refs[k] <= 0 {
		delete(t.refs, k)
		delete(t.known, k)
	}
}

// Size reports the number of tracked keys (for logging).
func (t *Tracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.known)
}
