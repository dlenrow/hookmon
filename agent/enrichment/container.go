package enrichment

import (
	"os"
	"strings"
)

// Runtime represents a detected container runtime.
type Runtime string

const (
	RuntimeNone       Runtime = "none"
	RuntimeDocker     Runtime = "docker"
	RuntimeContainerd Runtime = "containerd"
	RuntimeCRIO       Runtime = "cri-o"
	RuntimePodman     Runtime = "podman"
)

// DetectRuntime checks for the presence of container runtime sockets
// to determine which runtime is managing containers on this host.
func DetectRuntime() Runtime {
	sockets := map[string]Runtime{
		"/var/run/docker.sock":          RuntimeDocker,
		"/run/containerd/containerd.sock": RuntimeContainerd,
		"/var/run/crio/crio.sock":       RuntimeCRIO,
		"/run/podman/podman.sock":       RuntimePodman,
	}
	for path, rt := range sockets {
		if _, err := os.Stat(path); err == nil {
			return rt
		}
	}
	return RuntimeNone
}

// IsContainerized checks if the current process is running inside a container.
func IsContainerized() bool {
	// Check /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check cgroup for container patterns
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "kubepods") ||
		strings.Contains(content, "containerd")
}
