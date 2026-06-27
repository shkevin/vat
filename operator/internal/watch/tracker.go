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

func key(it WorkItem) string {
	if it.Digest != "" {
		return it.Digest
	}
	return "ref:" + it.ImageRef
}

// Observe returns the subset of items not seen before, marking them seen. The
// first observation of a digest/ref is "fresh" (would be scanned); repeats are
// dedup hits.
func (t *Tracker) Observe(items []WorkItem) []WorkItem {
	t.mu.Lock()
	defer t.mu.Unlock()
	var fresh []WorkItem
	for _, it := range items {
		k := key(it)
		if _, ok := t.known[k]; ok {
			continue
		}
		t.known[k] = struct{}{}
		fresh = append(fresh, it)
	}
	return fresh
}

// Size reports the number of tracked keys (for logging).
func (t *Tracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.known)
}
