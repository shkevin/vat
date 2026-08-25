package config

import "testing"

func TestLoadFromEnvUsesDefaultsAndRuntimeProfile(t *testing.T) {
	env := map[string]string{
		"VAT_URL":                        "http://vat-backend.vat.svc.cluster.local:8000",
		"VAT_OPERATOR_RUNTIME_PROFILE":   "k0s",
		"VAT_OPERATOR_NAMESPACE":         "vat-operator",
		"VAT_OPERATOR_CREDENTIAL_SECRET": "vat-operator-credentials",
	}

	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("LoadFromMap returned error: %v", err)
	}

	if cfg.VatURL != "http://vat-backend.vat.svc.cluster.local:8000" {
		t.Fatalf("VatURL = %q", cfg.VatURL)
	}
	if cfg.ScannerImage != "ghcr.io/shkevin/vat/scanner:latest" {
		t.Fatalf("ScannerImage = %q", cfg.ScannerImage)
	}
	if cfg.RuntimeProfile.Name != "k0s" {
		t.Fatalf("RuntimeProfile.Name = %q", cfg.RuntimeProfile.Name)
	}
	if cfg.CredentialsSecretName != "vat-operator-credentials" {
		t.Fatalf("CredentialsSecretName = %q", cfg.CredentialsSecretName)
	}
	if cfg.AdminTokenKey != "adminToken" {
		t.Fatalf("AdminTokenKey = %q", cfg.AdminTokenKey)
	}
	if cfg.ImageInventoryMode != "non-running" {
		t.Fatalf("ImageInventoryMode = %q, want non-running", cfg.ImageInventoryMode)
	}
}

func TestLoadFromEnvRequiresVatURL(t *testing.T) {
	_, err := LoadFromMap(map[string]string{})
	if err == nil {
		t.Fatal("LoadFromMap returned nil error without VAT_URL")
	}
}

func TestLoadFromEnvAllowsNonRunningImageInventoryMode(t *testing.T) {
	cfg, err := LoadFromMap(map[string]string{
		"VAT_URL":                           "http://vat-backend.vat.svc.cluster.local:8000",
		"VAT_OPERATOR_IMAGE_INVENTORY_MODE": "non-running",
	})
	if err != nil {
		t.Fatalf("LoadFromMap returned error: %v", err)
	}
	if cfg.ImageInventoryMode != "non-running" {
		t.Fatalf("ImageInventoryMode = %q, want non-running", cfg.ImageInventoryMode)
	}
}

func TestLoadFromEnvAllowsWorkloadImageInventoryMode(t *testing.T) {
	cfg, err := LoadFromMap(map[string]string{
		"VAT_URL":                           "http://vat-backend.vat.svc.cluster.local:8000",
		"VAT_OPERATOR_IMAGE_INVENTORY_MODE": "workload",
	})
	if err != nil {
		t.Fatalf("LoadFromMap returned error: %v", err)
	}
	if cfg.ImageInventoryMode != "workload" {
		t.Fatalf("ImageInventoryMode = %q, want workload", cfg.ImageInventoryMode)
	}
}

func TestExcludedNamespacesDefaultsToSelf(t *testing.T) {
	cfg, err := LoadFromMap(map[string]string{
		"VAT_URL":                "http://vat-backend.vat.svc.cluster.local:8000",
		"VAT_OPERATOR_NAMESPACE": "vat-operator",
	})
	if err != nil {
		t.Fatalf("LoadFromMap returned error: %v", err)
	}
	want := map[string]bool{"vat-operator": true, "kube-system": true, "kube-public": true, "kube-node-lease": true}
	if len(cfg.ExcludedNamespaceNames) != len(want) {
		t.Fatalf("ExcludedNamespaceNames = %v", cfg.ExcludedNamespaceNames)
	}
	for _, ns := range cfg.ExcludedNamespaceNames {
		if !want[ns] {
			t.Fatalf("unexpected excluded namespace %q in %v", ns, cfg.ExcludedNamespaceNames)
		}
	}
}

func TestExcludedNamespacesAddsCustomAndDedups(t *testing.T) {
	cfg, err := LoadFromMap(map[string]string{
		"VAT_URL":                          "http://vat-backend.vat.svc.cluster.local:8000",
		"VAT_OPERATOR_NAMESPACE":           "vat-operator",
		"VAT_OPERATOR_EXCLUDED_NAMESPACES": "team-a, vat-operator , team-b",
	})
	if err != nil {
		t.Fatalf("LoadFromMap returned error: %v", err)
	}
	got := map[string]bool{}
	for _, ns := range cfg.ExcludedNamespaceNames {
		if got[ns] {
			t.Fatalf("duplicate namespace %q in %v", ns, cfg.ExcludedNamespaceNames)
		}
		got[ns] = true
	}
	// self always excluded, custom appended, no dup for repeated self
	for _, ns := range []string{"vat-operator", "team-a", "team-b"} {
		if !got[ns] {
			t.Fatalf("missing excluded namespace %q in %v", ns, cfg.ExcludedNamespaceNames)
		}
	}
}
