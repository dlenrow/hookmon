// Package suppress counts the events sensors see and drop at the source
// because they cannot be a stealth hook: a browser's shared-memory segment,
// a library a package manager wrote, a dlopen of a library only root can
// change. The bus exports the counts as
// hookmon_events_suppressed_total{sensor,reason}, so what is dropped stays
// visible. docs/threat-model.md lists each reason.
package suppress

import (
	"sort"
	"sync"
)

// Reasons, the values of the reason label.
const (
	// NoBPFPattern: a /dev/shm segment whose name and creator say nothing
	// about BPF (shm_monitor).
	NoBPFPattern = "no_bpf_pattern"
	// PackageManager: a write by a process with a package manager in its
	// ancestry (linker_config, lib_integrity).
	PackageManager = "package_manager"
	// RootOnlyDirectory: a dlopen of a library whose directory, every
	// directory above it, and the file itself only root can write
	// (dlopen_monitor).
	RootOnlyDirectory = "root_only_directory"
	// SafeSearchPath: an LD_LIBRARY_PATH whose every entry is a standard
	// library directory or one only root can write (exec_injection).
	SafeSearchPath = "safe_search_path"
)

type key struct{ sensor, reason string }

var (
	mu     sync.Mutex
	counts = map[key]uint64{}
)

// Add counts one event sensor dropped for reason.
func Add(sensor, reason string) {
	mu.Lock()
	counts[key{sensor, reason}]++
	mu.Unlock()
}

// Get returns how many events sensor has dropped for reason.
func Get(sensor, reason string) uint64 {
	mu.Lock()
	defer mu.Unlock()
	return counts[key{sensor, reason}]
}

// Count is one sensor and reason with its total.
type Count struct {
	Sensor, Reason string
	N              uint64
}

// Snapshot returns every count, ordered by sensor and reason.
func Snapshot() []Count {
	mu.Lock()
	out := make([]Count, 0, len(counts))
	for k, n := range counts {
		out = append(out, Count{Sensor: k.sensor, Reason: k.reason, N: n})
	}
	mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sensor != out[j].Sensor {
			return out[i].Sensor < out[j].Sensor
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}
