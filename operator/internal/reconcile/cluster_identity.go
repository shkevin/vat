package reconcile

import (
	"context"
	"fmt"

	"gitlab.automatedhass.com/personal/vat/operator/internal/config"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ReconcileClusterIdentity publishes a stable cluster identifier for the scanner
// pods to consume (via configMapKeyRef). clusterId is the kube-system namespace
// UID — immutable and unique per cluster; clusterName defaults to it so multiple
// clusters never collide even when unnamed, and is overridable with a friendly
// name via VAT_OPERATOR_CLUSTER_NAME. Returns the resolved cluster name.
func ReconcileClusterIdentity(ctx context.Context, client kubernetes.Interface, cfg config.Config) (string, error) {
	ns, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get kube-system namespace for cluster identity: %w", err)
	}
	clusterID := string(ns.UID)
	clusterName := cfg.ClusterNameOverride
	if clusterName == "" {
		clusterName = clusterID
	}

	name := cfg.ClusterIdentityConfigMapName
	if name == "" {
		name = "vat-cluster-identity"
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vat-cluster-identity",
				"app.kubernetes.io/managed-by": "vat-operator",
			},
		},
		Data: map[string]string{"clusterId": clusterID, "clusterName": clusterName},
	}
	existing, err := client.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	} else if err == nil {
		cm.ResourceVersion = existing.ResourceVersion
		_, err = client.CoreV1().ConfigMaps(cfg.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return "", fmt.Errorf("publish cluster identity ConfigMap %s/%s: %w", cfg.Namespace, name, err)
	}
	return clusterName, nil
}
