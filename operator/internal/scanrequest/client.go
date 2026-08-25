// Package scanrequest creates and garbage-collects ScanRequest CRs — the durable,
// watchable scan queue the worker consumes (Phase 4 of the event-driven plan).
package scanrequest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"

	"github.com/shkevin/vat/operator/internal/watch"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var gvr = schema.GroupVersionResource{Group: "vat.io", Version: "v1alpha1", Resource: "scanrequests"}

// Client creates/GCs ScanRequest CRs in one namespace.
type Client struct {
	dyn       dynamic.Interface
	namespace string
}

// NewClient builds a ScanRequest writer from the operator's rest config.
func NewClient(cfg *rest.Config, namespace string) (*Client, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{dyn: dyn, namespace: namespace}, nil
}

// name derives a deterministic CR name from the dedup key so Create is
// idempotent — the object name IS the dedup key. Digest when known, else ref.
func name(item watch.WorkItem) string {
	key := item.Digest
	if key == "" {
		key = "ref:" + item.ImageRef
	}
	sum := sha256.Sum256([]byte(key))
	return "sr-" + hex.EncodeToString(sum[:])[:40]
}

// Create makes a ScanRequest for the work item. Returns (true, nil) when it
// actually created one; (false, nil) when it already existed (a dedup hit, so
// concurrent observers and the backstop converge safely); (false, err) otherwise.
func (c *Client) Create(ctx context.Context, item watch.WorkItem) (bool, error) {
	tags := []interface{}{}
	if item.Tag != "" {
		tags = append(tags, item.Tag)
	}
	scanTypes := make([]interface{}, 0, len(item.ScanTypes))
	for _, s := range item.ScanTypes {
		scanTypes = append(scanTypes, s)
	}
	observed := make([]interface{}, 0, len(item.ObservedRefs))
	for _, r := range item.ObservedRefs {
		observed = append(observed, map[string]interface{}{
			"namespace": r.Namespace, "kind": r.Kind, "name": r.Name, "container": r.Container,
		})
	}

	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "vat.io/v1alpha1",
		"kind":       "ScanRequest",
		"metadata":   map[string]interface{}{"name": name(item), "namespace": c.namespace},
		"spec": map[string]interface{}{
			"imageRef":     item.ImageRef,
			"digest":       item.Digest,
			"tags":         tags,
			"scanTypes":    scanTypes,
			"observedRefs": observed,
		},
	}}

	_, err := c.dyn.Resource(gvr).Namespace(c.namespace).Create(ctx, obj, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GC deletes done/failed ScanRequests older than ttl, bounding CR accumulation,
// and returns (deleted, pending) — pending feeds the backlog gauge. Keyed on
// creationTimestamp (always present) rather than parsing status times.
func (c *Client) GC(ctx context.Context, ttl time.Duration, now time.Time) (int, int, error) {
	list, err := c.dyn.Resource(gvr).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, err
	}
	deleted, pending := 0, 0
	for i := range list.Items {
		it := &list.Items[i]
		phase, _, _ := unstructured.NestedString(it.Object, "status", "phase")
		if phase == "" || phase == "pending" {
			pending++
		}
		if phase != "done" && phase != "failed" {
			continue
		}
		if now.Sub(it.GetCreationTimestamp().Time) < ttl {
			continue
		}
		if err := c.dyn.Resource(gvr).Namespace(c.namespace).Delete(ctx, it.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			log.Printf("event-driven GC: delete %s failed: %v", it.GetName(), err)
			continue
		}
		deleted++
	}
	return deleted, pending, nil
}
