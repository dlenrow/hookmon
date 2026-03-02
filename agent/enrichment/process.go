//go:build linux

package enrichment

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// EnrichProcess fills in process context fields on a HookEvent by reading
// from /proc for the given PID.
func EnrichProcess(evt *event.HookEvent) {
	pid := evt.PID
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Cmdline
	if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		evt.Cmdline = strings.ReplaceAll(string(data), "\x00", " ")
		evt.Cmdline = strings.TrimSpace(evt.Cmdline)
	}

	// Exe path
	if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		evt.ExePath = exe
	}

	// Cgroup
	if data, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			// cgroup v2: "0::/system.slice/..."
			if strings.HasPrefix(line, "0::") {
				evt.CgroupPath = strings.TrimPrefix(line, "0::")
				break
			}
		}
	}

	// Container ID from cgroup path
	evt.ContainerID = extractContainerID(evt.CgroupPath)
}

// extractContainerID attempts to extract a container ID from a cgroup path.
func extractContainerID(cgroupPath string) string {
	// Docker: /docker/<id>  or /system.slice/docker-<id>.scope
	// containerd: /system.slice/containerd-<id>.scope
	parts := strings.Split(cgroupPath, "/")
	for _, part := range parts {
		if len(part) == 64 && isHex(part) {
			return part
		}
		// docker-<id>.scope pattern
		if strings.HasPrefix(part, "docker-") && strings.HasSuffix(part, ".scope") {
			id := strings.TrimPrefix(part, "docker-")
			id = strings.TrimSuffix(id, ".scope")
			if len(id) == 64 && isHex(id) {
				return id
			}
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
