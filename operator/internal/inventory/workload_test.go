package inventory

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestImageTargetsFromDeploymentIncludesInitAndAppContainers(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "api",
			UID:       types.UID("uid-123"),
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry-creds"}},
					InitContainers: []corev1.Container{
						{Name: "migrate", Image: "registry.example.com/api-migrate:v1"},
					},
					Containers: []corev1.Container{
						{Name: "api", Image: "registry.example.com/api:v1"},
						{Name: "sidecar", Image: "registry.example.com/sidecar:v2"},
					},
				},
			},
		},
	}

	targets := ImageTargetsFromDeployment(deployment)
	if len(targets) != 3 {
		t.Fatalf("targets = %d, want 3", len(targets))
	}

	first := targets[0]
	if first.TargetKind != "Deployment" || first.TargetNamespace != "default" || first.TargetName != "api" {
		t.Fatalf("unexpected target identity: %#v", first)
	}
	if first.ContainerName != "migrate" || first.Image != "registry.example.com/api-migrate:v1" {
		t.Fatalf("unexpected first container target: %#v", first)
	}
	if len(first.ImagePullSecretNames) != 1 || first.ImagePullSecretNames[0] != "registry-creds" {
		t.Fatalf("image pull secrets = %#v", first.ImagePullSecretNames)
	}

	last := targets[2]
	if last.ContainerName != "sidecar" || last.Image != "registry.example.com/sidecar:v2" {
		t.Fatalf("unexpected last container target: %#v", last)
	}
}
