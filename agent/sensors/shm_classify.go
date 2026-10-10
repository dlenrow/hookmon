package sensors

import (
	"bytes"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// SHM pattern labels reported in SHMDetail.Pattern.
const (
	shmPatternBpftime    = "bpftime"
	shmPatternBPFRelated = "bpf_related"
	shmPatternUnknown    = "unknown"
)

// bpftimeShmNameEnv renames bpftime's segment. Upstream
// (github.com/eunomia-bpf/bpftime at 8da867d), get_global_shm_name() in
// runtime/src/handler/handler_manager.hpp:60-66 returns this variable's value,
// or DEFAULT_GLOBAL_SHM_NAME, "bpftime_maps_shm" (line 51), when it is unset.
// The syscall server creates the segment under that name
// (runtime/syscall-server/syscall_server_utils.cpp:129 and 143), through
// boost::interprocess::managed_shared_memory, i.e. shm_open().
const bpftimeShmNameEnv = "BPFTIME_GLOBAL_SHM_NAME"

// classifySHM returns the pattern and severity for a new /dev/shm segment
// named name, created by a process whose environment is env (NUL-terminated
// KEY=VALUE strings, as in /proc/<pid>/environ):
//
//   - "bpftime", CRITICAL: the name contains "bpftime" (bpftime's default,
//     bpftime_maps_shm, does), or the creator's environment sets
//     BPFTIME_GLOBAL_SHM_NAME to this name, which is how bpftime runs under
//     any other name.
//   - "bpf_related", ALERT: the name contains "bpf".
//   - "unknown", INFO: anything else. Many programs use /dev/shm.
func classifySHM(name string, env []byte) (string, event.Severity) {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "bpftime"), shmEnvNamesBpftime(env, name):
		return shmPatternBpftime, event.SeverityCritical
	case strings.Contains(lower, "bpf"):
		return shmPatternBPFRelated, event.SeverityAlert
	default:
		return shmPatternUnknown, event.SeverityInfo
	}
}

// shmEnvNamesBpftime reports whether env sets BPFTIME_GLOBAL_SHM_NAME to
// the segment name. boost::interprocess adds a leading '/' when the value has
// none, and glibc's shm_open strips leading slashes before it opens
// /dev/shm/<name>, so "x" and "/x" both create /dev/shm/x. Only entries
// followed by a NUL count: a copy cut short by the BPF size limit ends in a
// partial entry.
func shmEnvNamesBpftime(env []byte, name string) bool {
	if name == "" {
		return false
	}
	prefix := []byte(bpftimeShmNameEnv + "=")
	for {
		i := bytes.IndexByte(env, 0)
		if i < 0 {
			return false
		}
		entry := env[:i]
		env = env[i+1:]
		if !bytes.HasPrefix(entry, prefix) {
			continue
		}
		if strings.TrimLeft(string(entry[len(prefix):]), "/") == name {
			return true
		}
	}
}
