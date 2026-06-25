package inventory

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

type ImageTarget struct {
	TargetNamespace      string
	TargetKind           string
	TargetName           string
	TargetUID            string
	ContainerName        string
	Image                string
	ImagePullSecretNames []string
}

func ImageTargetsFromDeployment(deployment *appsv1.Deployment) []ImageTarget {
	if deployment == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		deployment.Namespace,
		"Deployment",
		deployment.Name,
		string(deployment.UID),
		deployment.Spec.Template.Spec,
	)
}

func ImageTargetsFromStatefulSet(statefulSet *appsv1.StatefulSet) []ImageTarget {
	if statefulSet == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		statefulSet.Namespace,
		"StatefulSet",
		statefulSet.Name,
		string(statefulSet.UID),
		statefulSet.Spec.Template.Spec,
	)
}

func ImageTargetsFromDaemonSet(daemonSet *appsv1.DaemonSet) []ImageTarget {
	if daemonSet == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		daemonSet.Namespace,
		"DaemonSet",
		daemonSet.Name,
		string(daemonSet.UID),
		daemonSet.Spec.Template.Spec,
	)
}

func ImageTargetsFromJob(job *batchv1.Job) []ImageTarget {
	if job == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		job.Namespace,
		"Job",
		job.Name,
		string(job.UID),
		job.Spec.Template.Spec,
	)
}

func ImageTargetsFromCronJob(cronJob *batchv1.CronJob) []ImageTarget {
	if cronJob == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		cronJob.Namespace,
		"CronJob",
		cronJob.Name,
		string(cronJob.UID),
		cronJob.Spec.JobTemplate.Spec.Template.Spec,
	)
}

func ImageTargetsFromPod(pod *corev1.Pod) []ImageTarget {
	if pod == nil {
		return nil
	}

	return imageTargetsFromPodSpec(
		pod.Namespace,
		"Pod",
		pod.Name,
		string(pod.UID),
		pod.Spec,
	)
}

func ImageTargetsFromRunningPod(pod *corev1.Pod) []ImageTarget {
	if pod == nil || pod.Status.Phase != corev1.PodRunning {
		return nil
	}

	imagePullSecrets := imagePullSecretNames(pod.Spec.ImagePullSecrets)
	containersByName := map[string]corev1.Container{}
	for _, container := range pod.Spec.InitContainers {
		containersByName[container.Name] = container
	}
	for _, container := range pod.Spec.Containers {
		containersByName[container.Name] = container
	}

	statuses := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	targets := make([]ImageTarget, 0, len(statuses))
	for _, status := range statuses {
		if status.State.Running == nil {
			continue
		}
		container, ok := containersByName[status.Name]
		if !ok || container.Image == "" {
			continue
		}
		targets = append(targets, ImageTarget{
			TargetNamespace:      pod.Namespace,
			TargetKind:           "Pod",
			TargetName:           pod.Name,
			TargetUID:            string(pod.UID),
			ContainerName:        container.Name,
			Image:                container.Image,
			ImagePullSecretNames: imagePullSecrets,
		})
	}
	return targets
}

func imageTargetsFromPodSpec(
	namespace string,
	kind string,
	name string,
	uid string,
	podSpec corev1.PodSpec,
) []ImageTarget {
	imagePullSecrets := imagePullSecretNames(podSpec.ImagePullSecrets)
	containers := append([]corev1.Container{}, podSpec.InitContainers...)
	containers = append(containers, podSpec.Containers...)

	targets := make([]ImageTarget, 0, len(containers))
	for _, container := range containers {
		if container.Image == "" {
			continue
		}
		targets = append(targets, ImageTarget{
			TargetNamespace:      namespace,
			TargetKind:           kind,
			TargetName:           name,
			TargetUID:            uid,
			ContainerName:        container.Name,
			Image:                container.Image,
			ImagePullSecretNames: imagePullSecrets,
		})
	}
	return targets
}

func imagePullSecretNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Name != "" {
			names = append(names, ref.Name)
		}
	}
	return names
}
