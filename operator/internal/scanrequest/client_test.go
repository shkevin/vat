package scanrequest

import (
	"context"
	"strings"
	"testing"
	"time"

	"gitlab.automatedhass.com/personal/vat/operator/internal/watch"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newFakeClient(objs ...runtime.Object) *Client {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{gvr: "ScanRequestList"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objs...)
	return &Client{dyn: dyn, namespace: "vat-operator"}
}

func sr(name, phase string, created time.Time) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "vat.io/v1alpha1",
		"kind":       "ScanRequest",
		"metadata":   map[string]interface{}{"name": name, "namespace": "vat-operator"},
		"spec":       map[string]interface{}{"imageRef": "x:1"},
		"status":     map[string]interface{}{"phase": phase},
	}}
	o.SetCreationTimestamp(metav1.NewTime(created))
	return o
}

func TestCreateIsIdempotentByDigest(t *testing.T) {
	c := newFakeClient()
	item := watch.WorkItem{ImageRef: "harbor/app:1", Digest: "sha256:" + strings.Repeat("a", 64), Tag: "1"}

	created, err := c.Create(context.Background(), item)
	if err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}
	// Same digest, different observing pod -> AlreadyExists -> dedup hit (created=false).
	created, err = c.Create(context.Background(), item)
	if err != nil || created {
		t.Fatalf("second create should be a no-op dedup hit, got created=%v err=%v", created, err)
	}
	list, err := c.dyn.Resource(gvr).Namespace("vat-operator").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want exactly 1 ScanRequest after duplicate create, got %d", len(list.Items))
	}
}

func TestGCDeletesFinishedPastTTLOnly(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	recent := now.Add(-10 * time.Minute)
	c := newFakeClient(
		sr("done-old", "done", old),       // delete
		sr("failed-old", "failed", old),   // delete
		sr("done-recent", "done", recent), // keep (within ttl)
		sr("pending-old", "pending", old), // keep (not finished)
	)

	deleted, pending, err := c.GC(context.Background(), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("want 2 deleted, got %d", deleted)
	}
	if pending != 1 {
		t.Fatalf("want 1 pending (pending-old), got %d", pending)
	}
	list, _ := c.dyn.Resource(gvr).Namespace("vat-operator").List(context.Background(), metav1.ListOptions{})
	got := map[string]bool{}
	for _, it := range list.Items {
		got[it.GetName()] = true
	}
	if got["done-old"] || got["failed-old"] {
		t.Errorf("finished+old requests should be gone: %v", got)
	}
	if !got["done-recent"] || !got["pending-old"] {
		t.Errorf("recent/unfinished requests should remain: %v", got)
	}
}
