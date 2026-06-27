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
	"gitlab.automatedhass.com/personal/vat/operator/internal/metrics"
	"gitlab.automatedhass.com/personal/vat/operator/internal/reconcile"
	"gitlab.automatedhass.com/personal/vat/operator/internal/scanrequest"
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

	// Event-driven informer runs alongside the poll, which stays the fallback
	// through Phase 4. Shadow mode logs only; active mode creates ScanRequests.
	if cfg.EventDrivenScansEnabled {
		go func() {
			if err := metrics.Serve(":9095"); err != nil {
				log.Printf("metrics server stopped: %v", err)
			}
		}()
		go runEventDriven(ctx, client, restConfig, cfg)
	}

	run(ctx, client, cfg)
}

func runEventDriven(ctx context.Context, client kubernetes.Interface, restConfig *rest.Config, cfg config.Config) {
	var warm []string
	if apiKey, err := watch.ReadAPIKey(ctx, client, cfg.Namespace, cfg.CredentialsSecretName, cfg.APIKeyKey); err != nil {
		log.Printf("event-driven: read api key failed, warming empty: %v", err)
	} else if digests, err := watch.FetchKnownDigests(ctx, cfg.VatURL, apiKey); err != nil {
		log.Printf("event-driven: known-digests warm-up failed, warming empty: %v", err)
	} else {
		warm = digests
	}
	tracker := watch.NewTracker(warm)
	log.Printf("event-driven: warmed dedup set with %d known digests (shadow=%t)", tracker.Size(), cfg.EventDrivenShadow)

	excluded := make(map[string]bool, len(cfg.ExcludedNamespaceNames))
	for _, ns := range cfg.ExcludedNamespaceNames {
		excluded[ns] = true
	}

	var writer watch.ScanRequestWriter
	if !cfg.EventDrivenShadow {
		w, err := scanrequest.NewClient(restConfig, cfg.Namespace)
		if err != nil {
			log.Fatalf("event-driven: build ScanRequest client: %v", err)
		}
		writer = w
		go runBackstop(ctx, client, w, tracker, excluded, cfg)
	}

	watch.Run(ctx, client, writer, tracker, excluded, cfg.EventDrivenShadow)
}

// runBackstop periodically fills coverage gaps (informer-missed pods) and GCs
// finished ScanRequests. The informer's resync is the fast backstop; this is the
// correctness floor for operator downtime / total watch failure.
func runBackstop(ctx context.Context, client kubernetes.Interface, writer *scanrequest.Client, tracker *watch.Tracker, excluded map[string]bool, cfg config.Config) {
	ticker := time.NewTicker(time.Duration(cfg.BackstopIntervalSeconds) * time.Second)
	defer ticker.Stop()
	ttl := time.Duration(cfg.ScanRequestTTLSeconds) * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if created, err := watch.Backstop(ctx, client, writer, tracker, excluded); err != nil {
				log.Printf("event-driven backstop: list pods failed: %v", err)
			} else if created > 0 {
				log.Printf("event-driven backstop: created %d missing ScanRequest(s)", created)
			}
			if deleted, pending, err := writer.GC(ctx, ttl, time.Now()); err != nil {
				log.Printf("event-driven GC: list failed: %v", err)
			} else {
				metrics.SetBacklog(pending)
				if deleted > 0 {
					log.Printf("event-driven GC: deleted %d finished ScanRequest(s); backlog=%d", deleted, pending)
				}
			}
		}
	}
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
