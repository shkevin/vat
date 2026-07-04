package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"
	"gitlab.automatedhass.com/personal/vat/operator/internal/inventory"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Result struct {
	PublishedImages   int
	WorkloadTargets   int
	KubernetesObjects int
}

func ReconcileDeploymentImageScans(
	ctx context.Context,
	client kubernetes.Interface,
	cfg config.Config,
) (Result, error) {
	deployments, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list deployments: %w", err)
	}

	result := Result{}
	for i := range deployments.Items {
		deployment := &deployments.Items[i]
		result = appendInventoryTargets(result, inventory.ImageTargetsFromDeployment(deployment))
	}

	return result, nil
}

type ImageInventory struct {
	GeneratedAt string               `json:"generatedAt"`
	Items       []ImageInventoryItem `json:"items"`
}

type ImageInventoryItem struct {
	Image       string              `json:"image"`
	ImageDigest string              `json:"imageDigest,omitempty"`
	Targets     []ImageInventoryRef `json:"targets"`
}

type ImageInventoryRef struct {
	Namespace            string   `json:"namespace"`
	Kind                 string   `json:"kind"`
	Name                 string   `json:"name"`
	UID                  string   `json:"uid,omitempty"`
	ContainerName        string   `json:"containerName"`
	ImagePullSecretNames []string `json:"imagePullSecrets,omitempty"`
}

func ReconcileWorkloadImageScans(
	ctx context.Context,
	client kubernetes.Interface,
	cfg config.Config,
) (Result, error) {
	result := Result{}
	excluded := namespaceExcluder(cfg.ExcludedNamespaceNames)
	targets := make([]inventory.ImageTarget, 0)
	if cfg.ImageInventoryMode == "runtime" {
		doc := BuildImageInventory(targets)
		if err := publishInventory(ctx, client, cfg, doc); err != nil {
			return result, err
		}
		return Result{PublishedImages: len(doc.Items), WorkloadTargets: len(targets)}, nil
	}
	if cfg.ImageInventoryMode == "running" {
		pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return result, fmt.Errorf("list pods: %w", err)
		}
		for i := range pods.Items {
			targets = append(targets, inventory.ImageTargetsFromRunningPod(&pods.Items[i])...)
		}

		targets = filterImageTargets(targets, excluded)
		doc := BuildImageInventory(targets)
		if err := publishInventory(ctx, client, cfg, doc); err != nil {
			return result, err
		}
		return Result{PublishedImages: len(doc.Items), WorkloadTargets: len(targets)}, nil
	}

	runningImages := map[string]struct{}{}
	if cfg.ImageInventoryMode == "non-running" {
		pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return result, fmt.Errorf("list pods: %w", err)
		}
		for i := range pods.Items {
			for _, target := range inventory.ImageTargetsFromRunningPod(&pods.Items[i]) {
				if image := strings.TrimSpace(target.Image); image != "" {
					runningImages[inventoryKey(image)] = struct{}{}
				}
			}
		}
	}

	deployments, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deployments.Items {
		targets = append(targets, inventory.ImageTargetsFromDeployment(&deployments.Items[i])...)
	}

	statefulSets, err := client.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range statefulSets.Items {
		targets = append(targets, inventory.ImageTargetsFromStatefulSet(&statefulSets.Items[i])...)
	}

	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range daemonSets.Items {
		targets = append(targets, inventory.ImageTargetsFromDaemonSet(&daemonSets.Items[i])...)
	}

	jobs, err := client.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, fmt.Errorf("list jobs: %w", err)
	}
	for i := range jobs.Items {
		targets = append(targets, inventory.ImageTargetsFromJob(&jobs.Items[i])...)
	}

	cronJobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, fmt.Errorf("list cronjobs: %w", err)
	}
	for i := range cronJobs.Items {
		targets = append(targets, inventory.ImageTargetsFromCronJob(&cronJobs.Items[i])...)
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, fmt.Errorf("list pods: %w", err)
	}
	for i := range pods.Items {
		if pods.Items[i].OwnerReferences != nil {
			continue
		}
		targets = append(targets, inventory.ImageTargetsFromPod(&pods.Items[i])...)
	}
	if cfg.ImageInventoryMode == "non-running" {
		targets = filterRunningImageTargets(targets, runningImages)
	}
	targets = filterImageTargets(targets, excluded)

	doc := BuildImageInventory(targets)
	if err := publishInventory(ctx, client, cfg, doc); err != nil {
		return result, err
	}
	return Result{PublishedImages: len(doc.Items), WorkloadTargets: len(targets)}, nil
}

// namespaceExcluder reports whether a namespace should be skipped. Cluster-scoped
// objects (empty namespace) are never excluded.
func namespaceExcluder(names []string) func(string) bool {
	if len(names) == 0 {
		return func(string) bool { return false }
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(ns string) bool { return ns != "" && set[ns] }
}

func filterImageTargets(targets []inventory.ImageTarget, excluded func(string) bool) []inventory.ImageTarget {
	filtered := make([]inventory.ImageTarget, 0, len(targets))
	for _, t := range targets {
		if excluded(t.TargetNamespace) {
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}

func BuildImageInventory(targets []inventory.ImageTarget) ImageInventory {
	byImage := map[string]*ImageInventoryItem{}
	for _, target := range targets {
		if !isScannableImageRef(target.Image) {
			continue
		}
		image := strings.TrimSpace(target.Image)
		key := inventoryKey(image)
		item := byImage[key]
		if item == nil {
			item = &ImageInventoryItem{Image: image, ImageDigest: digestFromImageRef(image)}
			byImage[key] = item
		}
		item.Targets = append(item.Targets, ImageInventoryRef{
			Namespace:            target.TargetNamespace,
			Kind:                 target.TargetKind,
			Name:                 target.TargetName,
			UID:                  target.TargetUID,
			ContainerName:        target.ContainerName,
			ImagePullSecretNames: append([]string{}, target.ImagePullSecretNames...),
		})
	}

	keys := make([]string, 0, len(byImage))
	for key := range byImage {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]ImageInventoryItem, 0, len(keys))
	for _, key := range keys {
		item := byImage[key]
		sort.Slice(item.Targets, func(i, j int) bool {
			left := item.Targets[i]
			right := item.Targets[j]
			return left.Namespace+"/"+left.Kind+"/"+left.Name+"/"+left.ContainerName < right.Namespace+"/"+right.Kind+"/"+right.Name+"/"+right.ContainerName
		})
		items = append(items, *item)
	}
	return ImageInventory{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Items: items}
}

func filterRunningImageTargets(targets []inventory.ImageTarget, runningImages map[string]struct{}) []inventory.ImageTarget {
	if len(targets) == 0 || len(runningImages) == 0 {
		return targets
	}
	filtered := make([]inventory.ImageTarget, 0, len(targets))
	for _, target := range targets {
		if _, ok := runningImages[inventoryKey(target.Image)]; ok {
			continue
		}
		filtered = append(filtered, target)
	}
	return filtered
}

func isScannableImageRef(image string) bool {
	value := strings.TrimSpace(strings.ToLower(image))
	if value == "" {
		return false
	}
	switch value {
	case "auto", "none", "<none>":
		return false
	default:
		return true
	}
}

func appendInventoryTargets(result Result, targets []inventory.ImageTarget) Result {
	doc := BuildImageInventory(targets)
	result.PublishedImages += len(doc.Items)
	result.WorkloadTargets += len(targets)
	return result
}

func publishInventory(ctx context.Context, client kubernetes.Interface, cfg config.Config, doc ImageInventory) error {
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal image inventory: %w", err)
	}
	name := cfg.InventoryConfigMapName
	if name == "" {
		name = "vat-scan-inventory"
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vat-scan-inventory",
				"app.kubernetes.io/managed-by": "vat-operator",
			},
		},
		Data: map[string]string{"images.json": string(payload)},
	}
	existing, err := client.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	} else if err == nil {
		cm.ResourceVersion = existing.ResourceVersion
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("publish image inventory ConfigMap %s/%s: %w", cfg.Namespace, name, err)
	}
	return nil
}

func inventoryKey(image string) string {
	if digest := digestFromImageRef(image); digest != "" {
		return digest
	}
	return image
}

func digestFromImageRef(image string) string {
	idx := strings.LastIndex(image, "@sha256:")
	if idx < 0 {
		return ""
	}
	return image[idx+1:]
}
