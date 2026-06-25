package profiles

import (
	"fmt"
	"strings"
)

type RuntimeProfileName string

const (
	RuntimeProfileAuto    RuntimeProfileName = "auto"
	RuntimeProfileGeneric RuntimeProfileName = "generic"
	RuntimeProfileKind    RuntimeProfileName = "kind"
	RuntimeProfileK0s     RuntimeProfileName = "k0s"
	RuntimeProfileK3s     RuntimeProfileName = "k3s"
)

type HostRuntimeAccessMode string

const (
	HostRuntimeAccessDirect            HostRuntimeAccessMode = "direct"
	HostRuntimeAccessContainerizedNode HostRuntimeAccessMode = "containerized-node"
)

type RuntimeProfile struct {
	Name                  RuntimeProfileName
	ContainerdSocketPath  string
	KubeletRootPath       string
	StaticPodManifestPath string
	HostRuntimeAccessMode HostRuntimeAccessMode
	NodeScanSupported     bool
}

func ResolveRuntimeProfile(name string) (RuntimeProfile, error) {
	normalized := RuntimeProfileName(strings.ToLower(strings.TrimSpace(name)))
	if normalized == "" || normalized == RuntimeProfileAuto {
		normalized = RuntimeProfileGeneric
	}

	profile, ok := runtimeProfiles[normalized]
	if !ok {
		return RuntimeProfile{}, fmt.Errorf("unknown runtime profile %q", name)
	}
	return profile, nil
}

var runtimeProfiles = map[RuntimeProfileName]RuntimeProfile{
	RuntimeProfileGeneric: {
		Name:                  RuntimeProfileGeneric,
		ContainerdSocketPath:  "/run/containerd/containerd.sock",
		KubeletRootPath:       "/var/lib/kubelet",
		StaticPodManifestPath: "/etc/kubernetes/manifests",
		HostRuntimeAccessMode: HostRuntimeAccessDirect,
		NodeScanSupported:     true,
	},
	RuntimeProfileKind: {
		Name:                  RuntimeProfileKind,
		ContainerdSocketPath:  "/run/containerd/containerd.sock",
		KubeletRootPath:       "/var/lib/kubelet",
		StaticPodManifestPath: "/etc/kubernetes/manifests",
		HostRuntimeAccessMode: HostRuntimeAccessContainerizedNode,
		NodeScanSupported:     false,
	},
	RuntimeProfileK0s: {
		Name:                  RuntimeProfileK0s,
		ContainerdSocketPath:  "/run/k0s/containerd.sock",
		KubeletRootPath:       "/var/lib/k0s/kubelet",
		StaticPodManifestPath: "/var/lib/k0s/manifests",
		HostRuntimeAccessMode: HostRuntimeAccessDirect,
		NodeScanSupported:     true,
	},
	RuntimeProfileK3s: {
		Name:                  RuntimeProfileK3s,
		ContainerdSocketPath:  "/run/k3s/containerd/containerd.sock",
		KubeletRootPath:       "/var/lib/kubelet",
		StaticPodManifestPath: "/var/lib/rancher/k3s/server/manifests",
		HostRuntimeAccessMode: HostRuntimeAccessDirect,
		NodeScanSupported:     true,
	},
}
