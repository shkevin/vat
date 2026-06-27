package watch

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// d64 builds a normalized 64-hex digest from a single repeated hex char.
func d64(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func itemByContainer(items []WorkItem, container string) (WorkItem, bool) {
	for _, it := range items {
		if it.ObservedRefs[0].Container == container {
			return it, true
		}
	}
	return WorkItem{}, false
}

func TestWorkItemsFromPodCoversInitEphemeralAndDigestFallback(t *testing.T) {
	initDigest := "sha256:1" + strings.Repeat("0", 63)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web-123"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Image: "ghcr.io/acme/init:1.2"}},
			Containers:     []corev1.Container{{Name: "app", Image: "harbor.io/acme/app:latest"}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox:1.36"},
			}},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", ImageID: "ghcr.io/acme/init@" + initDigest},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				// app: no digest in status (image not pulled yet) -> "" (not pinned in spec)
				{Name: "app", ImageID: ""},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{Name: "debug", ImageID: "docker.io/library/busybox@" + d64("a")},
			},
		},
	}

	items := WorkItemsFromPod(pod)
	if len(items) != 3 {
		t.Fatalf("want 3 work items (init+app+debug), got %d", len(items))
	}

	init, _ := itemByContainer(items, "init")
	if init.Digest != initDigest {
		t.Errorf("init digest = %q, want resolved from status", init.Digest)
	}
	if init.Tag != "1.2" {
		t.Errorf("init tag = %q, want 1.2", init.Tag)
	}

	app, _ := itemByContainer(items, "app")
	if app.Digest != "" {
		t.Errorf("app digest = %q, want empty (not pulled, not pinned)", app.Digest)
	}
	if app.Tag != "latest" {
		t.Errorf("app tag = %q, want latest", app.Tag)
	}

	debug, ok := itemByContainer(items, "debug")
	if !ok {
		t.Fatal("ephemeral container 'debug' missing from work items")
	}
	if debug.Digest != d64("a") {
		t.Errorf("debug digest = %q, want resolved from ephemeral status", debug.Digest)
	}
}

func TestWorkItemsFromPodDigestPinnedSpecRef(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "pinned"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "harbor.io/acme/app@" + d64("b")}},
		},
	}
	items := WorkItemsFromPod(pod)
	if len(items) != 1 || items[0].Digest != d64("b") {
		t.Fatalf("digest-pinned spec ref not resolved: %+v", items)
	}
}

func TestExtractDigestNormalizes(t *testing.T) {
	cases := map[string]string{
		"ghcr.io/x@sha256:" + strings.Repeat("A", 64): d64("a"), // lowercase
		"sha256:" + strings.Repeat("c", 64):           d64("c"),
		"docker.io/x@sha256:short":                    "", // < 12 hex
		"no-digest-here":                              "",
	}
	for in, want := range cases {
		if got := extractDigest(in); got != want {
			t.Errorf("extractDigest(%q) = %q, want %q", in, got, want)
		}
	}
}
