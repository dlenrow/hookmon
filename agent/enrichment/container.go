package enrichment

import "strings"

// runtimeScopePrefixes are the prefixes container runtimes give the cgroup
// of each container, followed by its 64-hex ID and, under the systemd
// cgroup driver, ".scope":
//
//	docker-<id>.scope           Docker, systemd driver
//	cri-containerd-<id>.scope   containerd's CRI plugin (Kubernetes), systemd driver
//	crio-<id>.scope, crio-<id>  CRI-O, systemd and cgroupfs drivers
//	libpod-<id>.scope, libpod-<id>  Podman (libpod), systemd and cgroupfs drivers
//
// The conmon monitors of CRI-O and Podman run in crio-conmon-<id>.scope and
// libpod-conmon-<id>.scope. They are host processes, not containers, and do
// not match: "conmon-<id>" is not a 64-hex ID.
var runtimeScopePrefixes = []string{"docker-", "cri-containerd-", "crio-", "libpod-"}

// ContainerID returns the container ID in a cgroup path, v1 or v2, or "" if
// the path is not a container's. Besides the prefixed forms above, it
// recognizes a bare 64-hex directory, which Docker (/docker/<id>) and
// Kubernetes with the cgroupfs driver (/kubepods/<qos>/pod<uid>/<id>) use.
// The innermost match wins, so a nested container reports its own ID.
func ContainerID(cgroupPath string) string {
	parts := strings.Split(cgroupPath, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if isContainerID(part) {
			return part
		}
		name := strings.TrimSuffix(part, ".scope")
		for _, prefix := range runtimeScopePrefixes {
			if id, ok := strings.CutPrefix(name, prefix); ok && isContainerID(id) {
				return id
			}
		}
	}
	return ""
}

// parseProcCgroup parses /proc/<pid>/cgroup. Each line is
// "hierarchy-ID:controller-list:path"; the cgroup v2 line is "0::path". It
// returns the v2 path, and the container ID from the v2 path or, failing
// that, from any v1 hierarchy (cgroup v1 and hybrid hosts).
func parseProcCgroup(data string) (v2Path, containerID string) {
	var v1Paths []string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[0] == "0" && fields[1] == "" {
			v2Path = fields[2]
			continue
		}
		v1Paths = append(v1Paths, fields[2])
	}
	containerID = ContainerID(v2Path)
	for _, p := range v1Paths {
		if containerID != "" {
			break
		}
		containerID = ContainerID(p)
	}
	return v2Path, containerID
}

func isContainerID(s string) bool {
	return len(s) == 64 && isHex(s)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
