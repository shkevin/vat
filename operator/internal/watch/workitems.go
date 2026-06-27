// Package watch builds the event-driven scan work set from a Pod informer and,
// in shadow mode, logs the scans the operator WOULD trigger for newly-seen image
// digests. It creates no ScanRequests yet (Phase 2 of the event-driven plan).
package watch

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// DefaultScanTypes are the image scan types a ScanRequest will carry. Hardcoded
// for now; lift to config when the Phase 3 worker needs to vary them.
var DefaultScanTypes = []string{"image-sca", "image-sbom", "container-stig"}

// ObservedRef records where an image was seen, for provenance/debugging.
type ObservedRef struct {
	Namespace string
	Kind      string
	Name      string
	Container string
}

// WorkItem is one image (by container) the operator may need to scan.
type WorkItem struct {
	ImageRef     string // ref as observed in the pod spec (registry/repo:tag)
	Digest       string // normalized "sha256:<hex>", or "" if not yet resolved
	Tag          string // observed tag, or "latest"
	ScanTypes    []string
	ObservedRefs []ObservedRef
}

// WorkItemsFromPod builds the per-container scan work set for a pod, combining
// spec images (init + regular + ephemeral) with resolved digests from status.
// A container with no status digest yet (image not pulled) gets Digest "" unless
// its spec ref is digest-pinned — the executor resolves it at scan time.
func WorkItemsFromPod(pod *corev1.Pod) []WorkItem {
	if pod == nil {
		return nil
	}

	images := map[string]string{} // container name -> spec image ref
	for _, c := range pod.Spec.InitContainers {
		if c.Image != "" {
			images[c.Name] = c.Image
		}
	}
	for _, c := range pod.Spec.Containers {
		if c.Image != "" {
			images[c.Name] = c.Image
		}
	}
	for _, ec := range pod.Spec.EphemeralContainers {
		if ec.Image != "" {
			images[ec.Name] = ec.Image
		}
	}

	digests := map[string]string{} // container name -> normalized digest from status
	addStatuses := func(ss []corev1.ContainerStatus) {
		for _, s := range ss {
			if d := extractDigest(s.ImageID); d != "" {
				digests[s.Name] = d
			}
		}
	}
	addStatuses(pod.Status.InitContainerStatuses)
	addStatuses(pod.Status.ContainerStatuses)
	addStatuses(pod.Status.EphemeralContainerStatuses)

	names := make([]string, 0, len(images))
	for name := range images {
		names = append(names, name)
	}
	sort.Strings(names) // stable order for deterministic logs/tests

	items := make([]WorkItem, 0, len(names))
	for _, name := range names {
		ref := images[name]
		digest := digests[name]
		if digest == "" {
			digest = extractDigest(ref) // digest-pinned spec ref
		}
		items = append(items, WorkItem{
			ImageRef:  ref,
			Digest:    digest,
			Tag:       tagFromRef(ref),
			ScanTypes: DefaultScanTypes,
			ObservedRefs: []ObservedRef{{
				Namespace: pod.Namespace,
				Kind:      "Pod",
				Name:      pod.Name,
				Container: name,
			}},
		})
	}
	return items
}

// extractDigest pulls a normalized "sha256:<hex>" out of an imageID or ref,
// mirroring the backend's normalize_image_digest (min 12 hex, capped at 64).
func extractDigest(s string) string {
	i := strings.LastIndex(s, "sha256:")
	if i < 0 {
		return ""
	}
	rest := s[i+len("sha256:"):]
	n := 0
	for n < len(rest) && isHex(rest[n]) {
		n++
	}
	hex := strings.ToLower(rest[:n])
	if len(hex) < 12 {
		return ""
	}
	if len(hex) > 64 {
		hex = hex[:64]
	}
	return "sha256:" + hex
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// tagFromRef returns the tag from registry/repo:tag, or "latest".
// ponytail: last-colon-after-last-slash heuristic — correct for registry/repo:tag
// and host:port/repo refs; swap in distribution/reference if a weird ref bites.
func tagFromRef(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i] // strip digest
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[colon+1:]
	}
	return "latest"
}
