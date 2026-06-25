package reconcile

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReconcileKubernetesInventoryPublishesObjectsAndStripsSecretData(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "api",
				ResourceVersion: "11",
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "registry.example.com/api:v1"}},
				}},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "db-password",
				ResourceVersion: "12",
			},
			Data: map[string][]byte{"password": []byte("super-secret")},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "app-config",
				ResourceVersion: "15",
			},
			Data: map[string]string{"config.yaml": "token: also-secret"},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "reader",
				ResourceVersion: "13",
			},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "cluster-admin-binding",
				ResourceVersion: "14",
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		},
	)

	result, err := ReconcileKubernetesInventory(ctx, client, testConfig())
	if err != nil {
		t.Fatalf("ReconcileKubernetesInventory returned error: %v", err)
	}
	if result.KubernetesObjects != 5 {
		t.Fatalf("KubernetesObjects = %d, want 5", result.KubernetesObjects)
	}

	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(ctx, "vat-k8s-inventory", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get k8s inventory ConfigMap: %v", err)
	}
	var doc KubernetesInventory
	payload, err := decodeCompressedInventory(cm.Data["kubernetes.json.gz.b64"])
	if err != nil {
		t.Fatalf("decode compressed inventory: %v", err)
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal k8s inventory: %v", err)
	}
	if len(doc.Items) != 5 {
		t.Fatalf("inventory item count = %d, want 5", len(doc.Items))
	}

	secret := findKubernetesInventoryItem(doc, "default", "Secret", "db-password")
	if secret == nil {
		t.Fatal("missing Secret metadata item")
	}
	if strings.Contains(secret.Manifest, "super-secret") {
		t.Fatal("secret data leaked into Kubernetes inventory")
	}
	if secret.ResourceVersion != "12" {
		t.Fatalf("secret resourceVersion = %q, want 12", secret.ResourceVersion)
	}
	configMap := findKubernetesInventoryItem(doc, "default", "ConfigMap", "app-config")
	if configMap == nil {
		t.Fatal("missing ConfigMap metadata item")
	}
	if strings.Contains(configMap.Manifest, "also-secret") {
		t.Fatal("configmap data leaked into Kubernetes inventory")
	}

	if findKubernetesInventoryItem(doc, "", "ClusterRoleBinding", "cluster-admin-binding") == nil {
		t.Fatal("missing ClusterRoleBinding inventory item")
	}
}

func decodeCompressedInventory(raw string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func findKubernetesInventoryItem(doc KubernetesInventory, namespace, kind, name string) *KubernetesInventoryItem {
	for i := range doc.Items {
		item := &doc.Items[i]
		if item.Namespace == namespace && item.Kind == kind && item.Name == name {
			return item
		}
	}
	return nil
}
