package watch

import "sync"

// Tracker is the in-memory dedup set, warmed from the backend's known-digests on
// startup and maintained from informer events. Keys on the resolved digest,
// falling back to the image ref when the digest is not yet known.
type Tracker struct {
	mu    sync.Mutex
	known map[string]struct{}
}

// NewTracker seeds the dedup set with already-known digests from the backend.
func NewTracker(warm []string) *Tracker {
	known := make(map[string]struct{}, len(warm))
	for _, d := range warm {
		if d != "" {
			known[d] = struct{}{}
		}
	}
	return &Tracker{known: known}
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

// Observe returns the subset of items not seen before, marking them seen. An item
// is a dedup hit if ANY of its keys (digest or ref) is already known; otherwise
// it's fresh. Either way all its keys are recorded, so a later observation of the
// same image — by ref or by digest — dedups.
func (t *Tracker) Observe(items []WorkItem) []WorkItem {
	t.mu.Lock()
	defer t.mu.Unlock()
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
		for _, k := range ks {
			t.known[k] = struct{}{}
		}
		if !seen {
			fresh = append(fresh, it)
		}
	}
	return fresh
}

// Size reports the number of tracked keys (for logging).
func (t *Tracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.known)
}
