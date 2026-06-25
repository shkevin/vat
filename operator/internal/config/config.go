package config

import (
	"fmt"
	"os"
	"strings"

	"gitlab.automatedhass.com/personal/vat/operator/internal/profiles"
)

const (
	defaultScannerImage     = "harbor.automatedhass.com/vat/scanner:latest"
	defaultOperatorNamepace = "vat-operator"
	defaultCredentialsName  = "vat-operator-credentials"
	defaultAdminTokenKey    = "adminToken"
)

type Config struct {
	VatURL                  string
	ScannerImage            string
	Namespace               string
	CredentialsSecretName   string
	AdminTokenKey           string
	APIKeyKey               string
	InventoryConfigMapName  string
	KubernetesConfigMapName string
	RuntimeProfile          profiles.RuntimeProfile
	NodeScanningEnabled     bool
	ServiceAccountName      string
	ImagePullSecretNames    []string
	BackoffLimit            int32
	TTLSecondsAfterFinish   int32
	MaxConcurrentScanJobs   int
	RescanIntervalSeconds   int
	ExcludedNamespaceNames  []string
	ImageInventoryMode      string
}

func LoadFromEnv() (Config, error) {
	return LoadFromMap(map[string]string{
		"VAT_URL":                            os.Getenv("VAT_URL"),
		"VAT_OPERATOR_SCANNER_IMAGE":         os.Getenv("VAT_OPERATOR_SCANNER_IMAGE"),
		"VAT_OPERATOR_NAMESPACE":             os.Getenv("VAT_OPERATOR_NAMESPACE"),
		"VAT_OPERATOR_CREDENTIAL_SECRET":     os.Getenv("VAT_OPERATOR_CREDENTIAL_SECRET"),
		"VAT_OPERATOR_ADMIN_TOKEN_KEY":       os.Getenv("VAT_OPERATOR_ADMIN_TOKEN_KEY"),
		"VAT_OPERATOR_RUNTIME_PROFILE":       os.Getenv("VAT_OPERATOR_RUNTIME_PROFILE"),
		"VAT_OPERATOR_NODE_SCANNING_ENABLED": os.Getenv("VAT_OPERATOR_NODE_SCANNING_ENABLED"),
		"VAT_OPERATOR_IMAGE_INVENTORY_MODE":  os.Getenv("VAT_OPERATOR_IMAGE_INVENTORY_MODE"),
	})
}

func LoadFromMap(env map[string]string) (Config, error) {
	vatURL := strings.TrimSpace(env["VAT_URL"])
	if vatURL == "" {
		return Config{}, fmt.Errorf("VAT_URL is required")
	}

	profile, err := profiles.ResolveRuntimeProfile(valueOrDefault(env["VAT_OPERATOR_RUNTIME_PROFILE"], string(profiles.RuntimeProfileAuto)))
	if err != nil {
		return Config{}, err
	}

	return Config{
		VatURL:                  vatURL,
		ScannerImage:            valueOrDefault(env["VAT_OPERATOR_SCANNER_IMAGE"], defaultScannerImage),
		Namespace:               valueOrDefault(env["VAT_OPERATOR_NAMESPACE"], defaultOperatorNamepace),
		CredentialsSecretName:   valueOrDefault(env["VAT_OPERATOR_CREDENTIAL_SECRET"], defaultCredentialsName),
		AdminTokenKey:           valueOrDefault(env["VAT_OPERATOR_ADMIN_TOKEN_KEY"], defaultAdminTokenKey),
		APIKeyKey:               "apiKey",
		InventoryConfigMapName:  "vat-scan-inventory",
		KubernetesConfigMapName: "vat-k8s-inventory",
		RuntimeProfile:          profile,
		NodeScanningEnabled:     parseBool(env["VAT_OPERATOR_NODE_SCANNING_ENABLED"]),
		ServiceAccountName:      "vat-operator-scanner",
		ImagePullSecretNames:    []string{"harbor-creds"},
		BackoffLimit:            1,
		TTLSecondsAfterFinish:   3600,
		MaxConcurrentScanJobs:   5,
		RescanIntervalSeconds:   3600,
		ExcludedNamespaceNames:  []string{"kube-system", "kube-public", "kube-node-lease"},
		ImageInventoryMode:      imageInventoryMode(env["VAT_OPERATOR_IMAGE_INVENTORY_MODE"]),
	}, nil
}

func valueOrDefault(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func imageInventoryMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "workload", "workloads", "desired":
		return "workload"
	case "running", "pods":
		return "running"
	default:
		return "runtime"
	}
}
