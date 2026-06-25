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
	if cfg.ScannerImage != "harbor.automatedhass.com/vat/scanner:latest" {
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
}

func TestLoadFromEnvRequiresVatURL(t *testing.T) {
	_, err := LoadFromMap(map[string]string{})
	if err == nil {
		t.Fatal("LoadFromMap returned nil error without VAT_URL")
	}
}
