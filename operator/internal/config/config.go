package config

import (
	"fmt"
	"os"
	"strconv"
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
	EventDrivenScansEnabled bool
	EventDrivenShadow       bool
	BackstopIntervalSeconds int
	ScanRequestTTLSeconds   int
}

func LoadFromEnv() (Config, error) {
	return LoadFromMap(map[string]string{
		"VAT_URL":                                os.Getenv("VAT_URL"),
		"VAT_OPERATOR_SCANNER_IMAGE":             os.Getenv("VAT_OPERATOR_SCANNER_IMAGE"),
		"VAT_OPERATOR_NAMESPACE":                 os.Getenv("VAT_OPERATOR_NAMESPACE"),
		"VAT_OPERATOR_CREDENTIAL_SECRET":         os.Getenv("VAT_OPERATOR_CREDENTIAL_SECRET"),
		"VAT_OPERATOR_ADMIN_TOKEN_KEY":           os.Getenv("VAT_OPERATOR_ADMIN_TOKEN_KEY"),
		"VAT_OPERATOR_RUNTIME_PROFILE":           os.Getenv("VAT_OPERATOR_RUNTIME_PROFILE"),
		"VAT_OPERATOR_NODE_SCANNING_ENABLED":     os.Getenv("VAT_OPERATOR_NODE_SCANNING_ENABLED"),
		"VAT_OPERATOR_IMAGE_INVENTORY_MODE":      os.Getenv("VAT_OPERATOR_IMAGE_INVENTORY_MODE"),
		"VAT_OPERATOR_EVENT_DRIVEN_SCANS":        os.Getenv("VAT_OPERATOR_EVENT_DRIVEN_SCANS"),
		"VAT_OPERATOR_EVENT_DRIVEN_SHADOW":       os.Getenv("VAT_OPERATOR_EVENT_DRIVEN_SHADOW"),
		"VAT_OPERATOR_BACKSTOP_INTERVAL_SECONDS": os.Getenv("VAT_OPERATOR_BACKSTOP_INTERVAL_SECONDS"),
		"VAT_OPERATOR_SCANREQUEST_TTL_SECONDS":   os.Getenv("VAT_OPERATOR_SCANREQUEST_TTL_SECONDS"),
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
		EventDrivenScansEnabled: parseBool(env["VAT_OPERATOR_EVENT_DRIVEN_SCANS"]),
		// Shadow defaults ON: enabling event-driven scans observes first; flip
		// VAT_OPERATOR_EVENT_DRIVEN_SHADOW=false to actually create ScanRequests.
		EventDrivenShadow:       parseBoolDefault(env["VAT_OPERATOR_EVENT_DRIVEN_SHADOW"], true),
		BackstopIntervalSeconds: parseIntDefault(env["VAT_OPERATOR_BACKSTOP_INTERVAL_SECONDS"], 18000), // 5h
		ScanRequestTTLSeconds:   parseIntDefault(env["VAT_OPERATOR_SCANREQUEST_TTL_SECONDS"], 86400),   // 24h
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

func parseBoolDefault(value string, def bool) bool {
	if strings.TrimSpace(value) == "" {
		return def
	}
	return parseBool(value)
}

func parseIntDefault(value string, def int) int {
	v := strings.TrimSpace(value)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func imageInventoryMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "workload", "workloads", "desired":
		return "workload"
	case "non-running", "nonrunning", "pending", "not-running":
		return "non-running"
	case "running", "pods":
		return "running"
	case "runtime":
		return "runtime"
	default:
		return "non-running"
	}
}
