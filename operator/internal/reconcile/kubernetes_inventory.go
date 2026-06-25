package reconcile

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

type KubernetesInventory struct {
	GeneratedAt string                    `json:"generatedAt"`
	Items       []KubernetesInventoryItem `json:"items"`
}

type KubernetesInventoryItem struct {
	Namespace       string `json:"namespace,omitempty"`
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Manifest        string `json:"manifest"`
}

func ReconcileKubernetesInventory(
	ctx context.Context,
	client kubernetes.Interface,
	cfg config.Config,
) (Result, error) {
	items := make([]KubernetesInventoryItem, 0)

	deployments, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list deployments for k8s inventory: %w", err)
	}
	for i := range deployments.Items {
		obj := deployments.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}
		items = append(items, kubernetesInventoryItem("Deployment", &obj, obj))
	}

	statefulSets, err := client.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list statefulsets for k8s inventory: %w", err)
	}
	for i := range statefulSets.Items {
		obj := statefulSets.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"}
		items = append(items, kubernetesInventoryItem("StatefulSet", &obj, obj))
	}

	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list daemonsets for k8s inventory: %w", err)
	}
	for i := range daemonSets.Items {
		obj := daemonSets.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"}
		items = append(items, kubernetesInventoryItem("DaemonSet", &obj, obj))
	}

	jobs, err := client.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list jobs for k8s inventory: %w", err)
	}
	for i := range jobs.Items {
		obj := jobs.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
		items = append(items, kubernetesInventoryItem("Job", &obj, obj))
	}

	cronJobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list cronjobs for k8s inventory: %w", err)
	}
	for i := range cronJobs.Items {
		obj := cronJobs.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "CronJob"}
		items = append(items, kubernetesInventoryItem("CronJob", &obj, obj))
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list pods for k8s inventory: %w", err)
	}
	for i := range pods.Items {
		obj := pods.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}
		items = append(items, kubernetesInventoryItem("Pod", &obj, obj))
	}

	services, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list services for k8s inventory: %w", err)
	}
	for i := range services.Items {
		obj := services.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}
		items = append(items, kubernetesInventoryItem("Service", &obj, obj))
	}

	configMaps, err := client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list configmaps for k8s inventory: %w", err)
	}
	for i := range configMaps.Items {
		obj := sanitizedConfigMap(configMaps.Items[i])
		items = append(items, kubernetesInventoryItem("ConfigMap", &obj, obj))
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list secrets for k8s inventory: %w", err)
	}
	for i := range secrets.Items {
		obj := sanitizedSecret(secrets.Items[i])
		items = append(items, kubernetesInventoryItem("Secret", &obj, obj))
	}

	serviceAccounts, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list serviceaccounts for k8s inventory: %w", err)
	}
	for i := range serviceAccounts.Items {
		obj := serviceAccounts.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}
		items = append(items, kubernetesInventoryItem("ServiceAccount", &obj, obj))
	}

	ingresses, err := client.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list ingresses for k8s inventory: %w", err)
	}
	for i := range ingresses.Items {
		obj := ingresses.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "Ingress"}
		items = append(items, kubernetesInventoryItem("Ingress", &obj, obj))
	}

	networkPolicies, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list networkpolicies for k8s inventory: %w", err)
	}
	for i := range networkPolicies.Items {
		obj := networkPolicies.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}
		items = append(items, kubernetesInventoryItem("NetworkPolicy", &obj, obj))
	}

	roles, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list roles for k8s inventory: %w", err)
	}
	for i := range roles.Items {
		obj := roles.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"}
		items = append(items, kubernetesInventoryItem("Role", &obj, obj))
	}

	roleBindings, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list rolebindings for k8s inventory: %w", err)
	}
	for i := range roleBindings.Items {
		obj := roleBindings.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"}
		items = append(items, kubernetesInventoryItem("RoleBinding", &obj, obj))
	}

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list clusterroles for k8s inventory: %w", err)
	}
	for i := range clusterRoles.Items {
		obj := clusterRoles.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}
		items = append(items, kubernetesInventoryItem("ClusterRole", &obj, obj))
	}

	clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list clusterrolebindings for k8s inventory: %w", err)
	}
	for i := range clusterRoleBindings.Items {
		obj := clusterRoleBindings.Items[i]
		obj.TypeMeta = metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}
		items = append(items, kubernetesInventoryItem("ClusterRoleBinding", &obj, obj))
	}

	doc := BuildKubernetesInventory(items)
	if err := publishKubernetesInventory(ctx, client, cfg, doc); err != nil {
		return Result{}, err
	}
	return Result{KubernetesObjects: len(doc.Items)}, nil
}

func BuildKubernetesInventory(items []KubernetesInventoryItem) KubernetesInventory {
	sort.Slice(items, func(i, j int) bool {
		left := items[i].Namespace + "/" + items[i].Kind + "/" + items[i].Name
		right := items[j].Namespace + "/" + items[j].Kind + "/" + items[j].Name
		return left < right
	})
	return KubernetesInventory{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Items:       items,
	}
}

func kubernetesInventoryItem(kind string, meta metav1.Object, manifest any) KubernetesInventoryItem {
	rendered, err := renderCompactManifest(manifest)
	if err != nil {
		rendered = []byte(fmt.Sprintf("kind: %s\nmetadata:\n  name: %s\n", kind, meta.GetName()))
	}
	return KubernetesInventoryItem{
		Namespace:       meta.GetNamespace(),
		Kind:            kind,
		Name:            meta.GetName(),
		UID:             string(meta.GetUID()),
		ResourceVersion: meta.GetResourceVersion(),
		Manifest:        string(rendered),
	}
}

func renderCompactManifest(manifest any) ([]byte, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	delete(obj, "status")
	if metadata, ok := obj["metadata"].(map[string]any); ok {
		delete(metadata, "managedFields")
		delete(metadata, "creationTimestamp")
	}
	return yaml.Marshal(obj)
}

func sanitizedConfigMap(configMap corev1.ConfigMap) corev1.ConfigMap {
	configMap.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}
	if configMap.Data != nil {
		keys := make(map[string]string, len(configMap.Data))
		for key := range configMap.Data {
			keys[key] = "<redacted>"
		}
		configMap.Data = keys
	}
	if configMap.BinaryData != nil {
		keys := make(map[string][]byte, len(configMap.BinaryData))
		for key := range configMap.BinaryData {
			keys[key] = []byte("<redacted>")
		}
		configMap.BinaryData = keys
	}
	return configMap
}

func sanitizedSecret(secret corev1.Secret) corev1.Secret {
	secret.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}
	secret.Data = nil
	secret.StringData = nil
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations["vat.io/secret-data-stripped"] = "true"
	return secret
}

func publishKubernetesInventory(ctx context.Context, client kubernetes.Interface, cfg config.Config, doc KubernetesInventory) error {
	payload, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal Kubernetes inventory: %w", err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(payload); err != nil {
		return fmt.Errorf("compress Kubernetes inventory: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close compressed Kubernetes inventory: %w", err)
	}
	name := cfg.KubernetesConfigMapName
	if name == "" {
		name = "vat-k8s-inventory"
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vat-k8s-inventory",
				"app.kubernetes.io/managed-by": "vat-operator",
			},
		},
		Data: map[string]string{
			"kubernetes.json.gz.b64": base64.StdEncoding.EncodeToString(compressed.Bytes()),
		},
	}
	existing, err := client.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	} else if err == nil {
		cm.ResourceVersion = existing.ResourceVersion
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("publish Kubernetes inventory ConfigMap %s/%s: %w", cfg.Namespace, name, err)
	}
	return nil
}

var _ = appsv1.Deployment{}
var _ = batchv1.Job{}
var _ = networkingv1.Ingress{}
var _ = rbacv1.Role{}
