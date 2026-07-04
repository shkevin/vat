package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"gitlab.automatedhass.com/personal/vat/operator/internal/metrics"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// resyncPeriod re-delivers all known pods periodically so a dropped watch event
// can't permanently miss an image. Cheap — it's metadata, not a scan. It also
// makes the informer itself a backstop for transient watch gaps.
const resyncPeriod = 20 * time.Minute

// ScanRequestWriter creates a ScanRequest for a work item (idempotent by name).
// Returns true when it actually created one, false on an AlreadyExists dedup hit.
type ScanRequestWriter interface {
	Create(ctx context.Context, item WorkItem) (bool, error)
}

// Run starts a cluster-wide Pod informer. In shadow mode it only LOGS the scans
// it would trigger; in active mode it creates a ScanRequest per fresh digest via
// writer. Blocks until ctx is cancelled.
func Run(ctx context.Context, client kubernetes.Interface, writer ScanRequestWriter, tracker *Tracker, excluded map[string]bool, shadow bool) {
	factory := informers.NewSharedInformerFactory(client, resyncPeriod)
	podInformer := factory.Core().V1().Pods().Informer()

	handle := func(obj interface{}) {
		pod, ok := obj.(*corev1.Pod)
		if !ok || pod == nil || excluded[pod.Namespace] {
			return
		}
		items := WorkItemsFromPod(pod)
		fresh := tracker.Observe(string(pod.UID), items)
		metrics.AddDedupHits(len(items) - len(fresh))
		for _, it := range fresh {
			if shadow {
				log.Printf(
					"event-driven shadow: WOULD scan digest=%q imageRef=%q tag=%q observedRef=%s/%s/%s",
					it.Digest, it.ImageRef, it.Tag, pod.Namespace, pod.Name, it.ObservedRefs[0].Container,
				)
				continue
			}
			if created, err := writer.Create(ctx, it); err != nil {
				log.Printf("event-driven: create ScanRequest for digest=%q imageRef=%q failed: %v", it.Digest, it.ImageRef, err)
			} else if created {
				metrics.IncCreated("event")
				log.Printf("event-driven: queued scan digest=%q imageRef=%q tag=%q", it.Digest, it.ImageRef, it.Tag)
			}
		}
	}

	// forget drops a deleted pod's image keys so a re-created image scans fresh.
	// Eviction is refcounted, so this only forgets an image once its last pod is
	// gone. Handles DeletedFinalStateUnknown tombstones delivered on relist, which
	// is how deletes during a watch gap are recovered.
	forget := func(obj interface{}) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				return
			}
			if pod, ok = tombstone.Obj.(*corev1.Pod); !ok {
				return
			}
		}
		tracker.Delete(string(pod.UID))
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handle,
		UpdateFunc: func(_, newObj interface{}) { handle(newObj) },
		DeleteFunc: forget,
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	log.Printf("event-driven: Pod informer synced (shadow=%t); watching all non-excluded namespaces", shadow)
	<-ctx.Done()
}

// Backstop lists all pods once and creates ScanRequests for anything the tracker
// hasn't already seen — the correctness floor for when the informer missed events
// (operator downtime, watch gaps). Idempotent CR naming makes re-creates no-ops.
func Backstop(ctx context.Context, client kubernetes.Interface, writer ScanRequestWriter, tracker *Tracker, excluded map[string]bool) (int, error) {
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	created := 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		if excluded[pod.Namespace] || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		items := WorkItemsFromPod(pod)
		fresh := tracker.Observe(string(pod.UID), items)
		metrics.AddDedupHits(len(items) - len(fresh))
		for _, it := range fresh {
			didCreate, err := writer.Create(ctx, it)
			if err != nil {
				log.Printf("event-driven backstop: create for digest=%q failed: %v", it.Digest, err)
				continue
			}
			if didCreate {
				created++
			}
		}
	}
	metrics.AddCreatedBackstop(created)
	return created, nil
}

// FetchKnownDigests warms the dedup set from the backend's read-only projection
// (GET /api/scan/known-digests). Best-effort: callers fall back to an empty set.
func FetchKnownDigests(ctx context.Context, vatURL, apiKey string) ([]string, error) {
	url := strings.TrimRight(vatURL, "/") + "/api/scan/known-digests"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("known-digests: status %d", resp.StatusCode)
	}
	var body struct {
		Digests []string `json:"digests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Digests, nil
}

// ReadAPIKey reads the ingest API key from the operator's credentials secret.
func ReadAPIKey(ctx context.Context, client kubernetes.Interface, namespace, secretName, key string) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(secret.Data[key])), nil
}
