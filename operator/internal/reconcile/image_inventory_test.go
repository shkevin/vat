package reconcile

import (
	"context"
	"encoding/json"
	"testing"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"
	"gitlab.automatedhass.com/personal/vat/operator/internal/inventory"

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

	result, err := ReconcileWorkloadImageScans(ctx, client, testConfig())
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

	result, err := ReconcileWorkloadImageScans(ctx, client, testConfig())
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
		ScannerImage:           "harbor.automatedhass.com/vat/scanner:latest",
		Namespace:              "vat-operator",
		CredentialsSecretName:  "vat-operator-credentials",
		AdminTokenKey:          "adminToken",
		APIKeyKey:              "apiKey",
		InventoryConfigMapName: "vat-scan-inventory",
		ServiceAccountName:     "vat-operator-scanner",
	}
}
