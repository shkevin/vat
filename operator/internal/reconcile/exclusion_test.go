package reconcile

import (
	"testing"

	"github.com/shkevin/vat/operator/internal/inventory"
)

func TestNamespaceExcluderKeepsClusterScoped(t *testing.T) {
	excluded := namespaceExcluder([]string{"vat-operator", "kube-system"})
	if !excluded("vat-operator") {
		t.Fatal("vat-operator should be excluded")
	}
	if excluded("default") {
		t.Fatal("default should not be excluded")
	}
	if excluded("") {
		t.Fatal("cluster-scoped (empty namespace) must never be excluded")
	}
}

func TestFilterImageTargetsDropsExcludedNamespace(t *testing.T) {
	excluded := namespaceExcluder([]string{"vat-operator"})
	targets := []inventory.ImageTarget{
		{TargetNamespace: "vat-operator", Image: "self:latest"},
		{TargetNamespace: "default", Image: "app:v1"},
	}
	got := filterImageTargets(targets, excluded)
	if len(got) != 1 || got[0].TargetNamespace != "default" {
		t.Fatalf("filterImageTargets = %+v, want only default", got)
	}
}

func TestFilterInventoryItemsKeepsClusterScoped(t *testing.T) {
	excluded := namespaceExcluder([]string{"vat-operator"})
	items := []KubernetesInventoryItem{
		{Namespace: "vat-operator", Kind: "Deployment", Name: "vat-operator"},
		{Namespace: "default", Kind: "Deployment", Name: "app"},
		{Namespace: "", Kind: "ClusterRole", Name: "admin"},
	}
	got := filterInventoryItems(items, excluded)
	if len(got) != 2 {
		t.Fatalf("filterInventoryItems kept %d items, want 2: %+v", len(got), got)
	}
	for _, it := range got {
		if it.Namespace == "vat-operator" {
			t.Fatalf("vat-operator item should have been dropped: %+v", it)
		}
	}
}
