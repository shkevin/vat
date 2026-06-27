package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// resyncPeriod re-delivers all known pods periodically so a dropped watch event
// can't permanently miss an image. Cheap — it's metadata, not a scan.
const resyncPeriod = 20 * time.Minute

// RunShadow starts a cluster-wide Pod informer and, in shadow mode, logs the
// scans the operator WOULD trigger for newly-seen image digests. It creates no
// ScanRequests. Blocks until ctx is cancelled.
func RunShadow(ctx context.Context, client kubernetes.Interface, excluded map[string]bool, warm []string) {
	tracker := NewTracker(warm)
	log.Printf("event-driven shadow: warmed dedup set with %d known digests", tracker.Size())

	factory := informers.NewSharedInformerFactory(client, resyncPeriod)
	podInformer := factory.Core().V1().Pods().Informer()

	handle := func(obj interface{}) {
		pod, ok := obj.(*corev1.Pod)
		if !ok || pod == nil || excluded[pod.Namespace] {
			return
		}
		for _, it := range tracker.Observe(WorkItemsFromPod(pod)) {
			log.Printf(
				"event-driven shadow: WOULD scan digest=%q imageRef=%q tag=%q scanTypes=%v observedRef=%s/%s/%s",
				it.Digest, it.ImageRef, it.Tag, it.ScanTypes, pod.Namespace, pod.Name, it.ObservedRefs[0].Container,
			)
		}
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handle,
		UpdateFunc: func(_, newObj interface{}) { handle(newObj) },
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	log.Printf("event-driven shadow: Pod informer synced; watching all non-excluded namespaces")
	<-ctx.Done()
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
