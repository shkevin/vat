package reconcile

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shkevin/vat/operator/internal/config"
	"github.com/shkevin/vat/operator/internal/inventory"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReconcileWorkloadImageScansPublishesDedupedInventory(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vat-scan-inventory", Namespace: "vat-operator"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("uid-api")},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "api", Image: "registry.example.com/api:v1"},
						{Name: "sidecar", Image: "registry.example.com/shared:v1"},
					},
				}},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "worker", UID: types.UID("uid-worker")},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "worker", Image: "registry.example.com/shared:v1"},
					},
				}},
			},
		},
	)

	result, err := ReconcileWorkloadImageScans(ctx, client, workloadTestConfig())
	if err != nil {
		t.Fatalf("ReconcileWorkloadImageScans returned error: %v", err)
	}
	if result.PublishedImages != 2 {
		t.Fatalf("PublishedImages = %d, want 2", result.PublishedImages)
	}
	if result.WorkloadTargets != 3 {
		t.Fatalf("WorkloadTargets = %d, want 3", result.WorkloadTargets)
	}

	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-scan-inventory", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get inventory ConfigMap: %v", err)
	}
	var doc ImageInventory
	if err := json.Unmarshal([]byte(cm.Data["images.json"]), &doc); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if len(doc.Items) != 2 {
		t.Fatalf("inventory item count = %d, want 2", len(doc.Items))
	}

	shared := findInventoryItem(doc, "registry.example.com/shared:v1")
	if shared == nil {
		t.Fatal("missing shared image")
	}
	if len(shared.Targets) != 2 {
		t.Fatalf("shared target count = %d, want 2", len(shared.Targets))
	}
}

func TestReconcileWorkloadImageScansCreatesInventoryConfigMapIfMissing(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("uid-api")},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
			}},
		},
	})

	result, err := ReconcileWorkloadImageScans(ctx, client, workloadTestConfig())
	if err != nil {
		t.Fatalf("ReconcileWorkloadImageScans returned error: %v", err)
	}
	if result.PublishedImages != 1 {
		t.Fatalf("PublishedImages = %d, want 1", result.PublishedImages)
	}
	if _, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-scan-inventory", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected inventory ConfigMap to be created: %v", err)
	}
}

func TestReconcileWorkloadImageScansDefaultsToRunningPodContainers(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vat-scan-inventory", Namespace: "vat-operator"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api-running", UID: types.UID("uid-api-running")},
			Spec: corev1.PodSpec{
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry-creds"}},
				InitContainers:   []corev1.Container{{Name: "init", Image: "registry.example.com/init:v1"}},
				Containers: []corev1.Container{
					{Name: "api", Image: "registry.example.com/api:v1"},
					{Name: "sidecar", Image: "registry.example.com/sidecar:v1"},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				InitContainerStatuses: []corev1.ContainerStatus{{
					Name: "init",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{},
					},
				}},
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "api",
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{},
						},
					},
					{
						Name: "sidecar",
						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{},
						},
					},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api-pending", UID: types.UID("uid-api-pending")},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/pending:v1"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodPending},
		},
	)

	result, err := ReconcileWorkloadImageScans(ctx, client, runningTestConfig())
	if err != nil {
		t.Fatalf("ReconcileWorkloadImageScans returned error: %v", err)
	}
	if result.PublishedImages != 1 {
		t.Fatalf("PublishedImages = %d, want 1", result.PublishedImages)
	}
	if result.WorkloadTargets != 1 {
		t.Fatalf("WorkloadTargets = %d, want 1", result.WorkloadTargets)
	}

	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-scan-inventory", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get inventory ConfigMap: %v", err)
	}
	var doc ImageInventory
	if err := json.Unmarshal([]byte(cm.Data["images.json"]), &doc); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if len(doc.Items) != 1 || doc.Items[0].Image != "registry.example.com/api:v1" {
		t.Fatalf("inventory items = %#v, want only running api image", doc.Items)
	}
	target := doc.Items[0].Targets[0]
	if target.Kind != "Pod" || target.Name != "api-running" || target.ContainerName != "api" {
		t.Fatalf("target = %#v, want running api pod target", target)
	}
	if len(target.ImagePullSecretNames) != 1 || target.ImagePullSecretNames[0] != "registry-creds" {
		t.Fatalf("ImagePullSecretNames = %#v, want registry-creds", target.ImagePullSecretNames)
	}
}

func TestReconcileWorkloadImageScansPublishesOnlyNonRunningWorkloadImages(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vat-scan-inventory", Namespace: "vat-operator"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("uid-api")},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
				}},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pending", UID: types.UID("uid-pending")},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/pending:v1"}},
				}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api-running", UID: types.UID("uid-api-running")},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "api",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "pending-pod",
				UID:       types.UID("uid-pending-pod"),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "pending-abc123",
					UID:        types.UID("uid-pending-rs"),
				}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/pending:v1"}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "api",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{},
					},
				}},
			},
		},
	)

	result, err := ReconcileWorkloadImageScans(ctx, client, nonRunningTestConfig())
	if err != nil {
		t.Fatalf("ReconcileWorkloadImageScans returned error: %v", err)
	}
	if result.PublishedImages != 1 {
		t.Fatalf("PublishedImages = %d, want 1", result.PublishedImages)
	}
	if result.WorkloadTargets != 1 {
		t.Fatalf("WorkloadTargets = %d, want 1", result.WorkloadTargets)
	}

	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-scan-inventory", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get inventory ConfigMap: %v", err)
	}
	var doc ImageInventory
	if err := json.Unmarshal([]byte(cm.Data["images.json"]), &doc); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if len(doc.Items) != 1 || doc.Items[0].Image != "registry.example.com/pending:v1" {
		t.Fatalf("inventory items = %#v, want only pending image", doc.Items)
	}
}

func TestReconcileWorkloadImageScansRuntimeModePublishesEmptyCentralInventory(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "vat-scan-inventory", Namespace: "vat-operator"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("uid-api")},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
				}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api-running", UID: types.UID("uid-api-running")},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "api",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				}},
			},
		},
	)

	result, err := ReconcileWorkloadImageScans(ctx, client, testConfig())
	if err != nil {
		t.Fatalf("ReconcileWorkloadImageScans returned error: %v", err)
	}
	if result.PublishedImages != 0 || result.WorkloadTargets != 0 {
		t.Fatalf("result = %#v, want empty central inventory in runtime mode", result)
	}
	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-scan-inventory", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get inventory ConfigMap: %v", err)
	}
	var doc ImageInventory
	if err := json.Unmarshal([]byte(cm.Data["images.json"]), &doc); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if len(doc.Items) != 0 {
		t.Fatalf("inventory item count = %d, want 0", len(doc.Items))
	}
}

func TestBuildImageInventorySkipsPlaceholderImages(t *testing.T) {
	doc := BuildImageInventory([]inventory.ImageTarget{
		{
			TargetNamespace: "istio-system",
			TargetKind:      "Deployment",
			TargetName:      "gateway",
			ContainerName:   "istio-proxy",
			Image:           "auto",
		},
		{
			TargetNamespace: "default",
			TargetKind:      "Deployment",
			TargetName:      "api",
			ContainerName:   "api",
			Image:           "registry.example.com/api:v1",
		},
	})
	if len(doc.Items) != 1 {
		t.Fatalf("inventory item count = %d, want 1", len(doc.Items))
	}
	if doc.Items[0].Image != "registry.example.com/api:v1" {
		t.Fatalf("inventory image = %q", doc.Items[0].Image)
	}
}

func TestBuildImageInventoryIncludesPullSecretReferences(t *testing.T) {
	doc := BuildImageInventory([]inventory.ImageTarget{
		{
			TargetNamespace:      "apps",
			TargetKind:           "Deployment",
			TargetName:           "api",
			ContainerName:        "api",
			Image:                "harbor.example.com/apps/api:v1",
			ImagePullSecretNames: []string{"harbor-creds"},
		},
	})
	if len(doc.Items) != 1 {
		t.Fatalf("inventory item count = %d, want 1", len(doc.Items))
	}
	if len(doc.Items[0].Targets) != 1 {
		t.Fatalf("target count = %d, want 1", len(doc.Items[0].Targets))
	}
	if got := doc.Items[0].Targets[0].ImagePullSecretNames; len(got) != 1 || got[0] != "harbor-creds" {
		t.Fatalf("ImagePullSecretNames = %#v, want harbor-creds", got)
	}
}

func findInventoryItem(doc ImageInventory, image string) *ImageInventoryItem {
	for i := range doc.Items {
		if doc.Items[i].Image == image {
			return &doc.Items[i]
		}
	}
	return nil
}

func testConfig() config.Config {
	return config.Config{
		VatURL:                 "http://vat-backend.vat.svc.cluster.local:8000",
		ScannerImage:           "ghcr.io/shkevin/vat/scanner:latest",
		Namespace:              "vat-operator",
		CredentialsSecretName:  "vat-operator-credentials",
		AdminTokenKey:          "adminToken",
		APIKeyKey:              "apiKey",
		InventoryConfigMapName: "vat-scan-inventory",
		ServiceAccountName:     "vat-operator-scanner",
		ImageInventoryMode:     "runtime",
	}
}

func runningTestConfig() config.Config {
	cfg := testConfig()
	cfg.ImageInventoryMode = "running"
	return cfg
}

func workloadTestConfig() config.Config {
	cfg := testConfig()
	cfg.ImageInventoryMode = "workload"
	return cfg
}

func nonRunningTestConfig() config.Config {
	cfg := testConfig()
	cfg.ImageInventoryMode = "non-running"
	return cfg
}
