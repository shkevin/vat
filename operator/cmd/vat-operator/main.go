package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"
	"gitlab.automatedhass.com/personal/vat/operator/internal/reconcile"
	"gitlab.automatedhass.com/personal/vat/operator/internal/watch"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "path to kubeconfig for out-of-cluster development")
	flag.Parse()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	restConfig, err := buildKubernetesConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("build Kubernetes config: %v", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("create Kubernetes client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf(
		"starting VAT operator: namespace=%s scannerImage=%s runtimeProfile=%s nodeScanning=%t eventDrivenScans=%t",
		cfg.Namespace,
		cfg.ScannerImage,
		cfg.RuntimeProfile.Name,
		cfg.NodeScanningEnabled,
		cfg.EventDrivenScansEnabled,
	)

	// Event-driven shadow informer runs alongside the poll (which stays the
	// source of truth until Phase 4). Log-only: it creates no ScanRequests.
	if cfg.EventDrivenScansEnabled {
		go runShadow(ctx, client, cfg)
	}

	run(ctx, client, cfg)
}

func runShadow(ctx context.Context, client kubernetes.Interface, cfg config.Config) {
	var warm []string
	if apiKey, err := watch.ReadAPIKey(ctx, client, cfg.Namespace, cfg.CredentialsSecretName, cfg.APIKeyKey); err != nil {
		log.Printf("event-driven shadow: read api key failed, warming empty: %v", err)
	} else if digests, err := watch.FetchKnownDigests(ctx, cfg.VatURL, apiKey); err != nil {
		log.Printf("event-driven shadow: known-digests warm-up failed, warming empty: %v", err)
	} else {
		warm = digests
	}

	excluded := make(map[string]bool, len(cfg.ExcludedNamespaceNames))
	for _, ns := range cfg.ExcludedNamespaceNames {
		excluded[ns] = true
	}
	watch.RunShadow(ctx, client, excluded, warm)
}

func run(ctx context.Context, client kubernetes.Interface, cfg config.Config) {
	interval := time.Duration(cfg.RescanIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		result, err := reconcile.ReconcileWorkloadImageScans(ctx, client, cfg)
		if err != nil {
			log.Printf("workload image inventory reconcile failed: %v", err)
		} else {
			log.Printf(
				"workload image inventory reconcile complete: publishedImages=%d workloadTargets=%d",
				result.PublishedImages,
				result.WorkloadTargets,
			)
		}

		kubernetesResult, err := reconcile.ReconcileKubernetesInventory(ctx, client, cfg)
		if err != nil {
			log.Printf("Kubernetes object inventory reconcile failed: %v", err)
		} else {
			log.Printf(
				"Kubernetes object inventory reconcile complete: kubernetesObjects=%d",
				kubernetesResult.KubernetesObjects,
			)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func buildKubernetesConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
