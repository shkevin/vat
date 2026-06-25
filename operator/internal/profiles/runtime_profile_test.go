package profiles

import "testing"

func TestResolveRuntimeProfileUsesK0sDefaults(t *testing.T) {
	profile, err := ResolveRuntimeProfile("k0s")
	if err != nil {
		t.Fatalf("ResolveRuntimeProfile returned error: %v", err)
	}

	if profile.Name != RuntimeProfileK0s {
		t.Fatalf("Name = %q, want %q", profile.Name, RuntimeProfileK0s)
	}
	if profile.ContainerdSocketPath != "/run/k0s/containerd.sock" {
		t.Fatalf("ContainerdSocketPath = %q", profile.ContainerdSocketPath)
	}
	if profile.KubeletRootPath != "/var/lib/k0s/kubelet" {
		t.Fatalf("KubeletRootPath = %q", profile.KubeletRootPath)
	}
	if profile.StaticPodManifestPath != "/var/lib/k0s/manifests" {
		t.Fatalf("StaticPodManifestPath = %q", profile.StaticPodManifestPath)
	}
	if !profile.NodeScanSupported {
		t.Fatal("NodeScanSupported = false, want true")
	}
}

func TestResolveRuntimeProfileUsesKindDefaults(t *testing.T) {
	profile, err := ResolveRuntimeProfile("kind")
	if err != nil {
		t.Fatalf("ResolveRuntimeProfile returned error: %v", err)
	}

	if profile.Name != RuntimeProfileKind {
		t.Fatalf("Name = %q, want %q", profile.Name, RuntimeProfileKind)
	}
	if profile.ContainerdSocketPath != "/run/containerd/containerd.sock" {
		t.Fatalf("ContainerdSocketPath = %q", profile.ContainerdSocketPath)
	}
	if profile.HostRuntimeAccessMode != HostRuntimeAccessContainerizedNode {
		t.Fatalf("HostRuntimeAccessMode = %q", profile.HostRuntimeAccessMode)
	}
	if profile.NodeScanSupported {
		t.Fatal("NodeScanSupported = true, want false unless host runtime is explicitly exposed")
	}
}

func TestResolveRuntimeProfileAutoFallsBackToGeneric(t *testing.T) {
	profile, err := ResolveRuntimeProfile("auto")
	if err != nil {
		t.Fatalf("ResolveRuntimeProfile returned error: %v", err)
	}

	if profile.Name != RuntimeProfileGeneric {
		t.Fatalf("Name = %q, want %q", profile.Name, RuntimeProfileGeneric)
	}
	if profile.ContainerdSocketPath != "/run/containerd/containerd.sock" {
		t.Fatalf("ContainerdSocketPath = %q", profile.ContainerdSocketPath)
	}
}

func TestResolveRuntimeProfileRejectsUnknownProfile(t *testing.T) {
	_, err := ResolveRuntimeProfile("not-a-cluster")
	if err == nil {
		t.Fatal("ResolveRuntimeProfile returned nil error for unknown profile")
	}
}
