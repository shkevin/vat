package reconcile

import (
	"context"
	"testing"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"
	"gitlab.automatedhass.com/personal/vat/operator/internal/profiles"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func kubeSystem(uid string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(uid)}}
}

func TestClusterIdentityDefaultsToProfileAndShortUID(t *testing.T) {
	client := fake.NewSimpleClientset(kubeSystem("1a2b3c4d-5e6f-7890-abcd-ef0123456789"))
	cfg := config.Config{
		Namespace:                    "vat-operator",
		ClusterIdentityConfigMapName: "vat-cluster-identity",
		RuntimeProfile:               profiles.RuntimeProfile{Name: profiles.RuntimeProfileK3s},
	}

	name, err := ReconcileClusterIdentity(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("ReconcileClusterIdentity error: %v", err)
	}
	// friendlier default: "<profile>-<short-uid>", readable + unique.
	if name != "k3s-1a2b3c4d" {
		t.Fatalf("clusterName = %q, want k3s-1a2b3c4d", name)
	}
	cm, err := client.CoreV1().ConfigMaps("vat-operator").Get(context.Background(), "vat-cluster-identity", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get published ConfigMap: %v", err)
	}
	// clusterId keeps the full UID; only the display name is shortened.
	if cm.Data["clusterId"] != "1a2b3c4d-5e6f-7890-abcd-ef0123456789" || cm.Data["clusterName"] != "k3s-1a2b3c4d" {
		t.Fatalf("ConfigMap data = %v", cm.Data)
	}
}

func TestDefaultClusterNameFallsBackWhenProfileMissing(t *testing.T) {
	if got := defaultClusterName("", "abcdef1234"); got != "cluster-abcdef12" {
		t.Fatalf("defaultClusterName empty profile = %q, want cluster-abcdef12", got)
	}
	if got := defaultClusterName("auto", "abcdef1234"); got != "cluster-abcdef12" {
		t.Fatalf("defaultClusterName auto profile = %q, want cluster-abcdef12", got)
	}
}

func TestClusterIdentityUsesOverrideNameKeepsUIDAsId(t *testing.T) {
	client := fake.NewSimpleClientset(kubeSystem("uid-9999"))
	cfg := config.Config{Namespace: "vat-operator", ClusterIdentityConfigMapName: "vat-cluster-identity", ClusterNameOverride: "prod-east"}

	name, err := ReconcileClusterIdentity(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("ReconcileClusterIdentity error: %v", err)
	}
	if name != "prod-east" {
		t.Fatalf("clusterName = %q, want override", name)
	}
	cm, _ := client.CoreV1().ConfigMaps("vat-operator").Get(context.Background(), "vat-cluster-identity", metav1.GetOptions{})
	if cm.Data["clusterName"] != "prod-east" || cm.Data["clusterId"] != "uid-9999" {
		t.Fatalf("ConfigMap data = %v (id should stay UID, name is override)", cm.Data)
	}
}

func TestClusterIdentityRepublishIsIdempotent(t *testing.T) {
	client := fake.NewSimpleClientset(kubeSystem("uid-1"))
	cfg := config.Config{Namespace: "vat-operator", ClusterIdentityConfigMapName: "vat-cluster-identity"}
	if _, err := ReconcileClusterIdentity(context.Background(), client, cfg); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if _, err := ReconcileClusterIdentity(context.Background(), client, cfg); err != nil {
		t.Fatalf("republish (update path) failed: %v", err)
	}
}
