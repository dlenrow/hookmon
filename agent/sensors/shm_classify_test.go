package sensors

import (
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// shmPtrEnv builds a /proc/<pid>/environ-style buffer.
func shmPtrEnv(vars ...string) []byte {
	var b []byte
	for _, v := range vars {
		b = append(b, v...)
		b = append(b, 0)
	}
	return b
}

func TestShmPtrClassifySHM(t *testing.T) {
	plainEnv := shmPtrEnv("PATH=/usr/bin", "HOME=/root")
	tests := []struct {
		name     string
		segment  string
		env      []byte
		pattern  string
		severity event.Severity
	}{
		{"bpftime default name", "bpftime_maps_shm", plainEnv, "bpftime", event.SeverityCritical},
		{"bpftime in name, any case", "BPFTIME_TEST_SHM_JSON_IMPORT_EXPORT", nil, "bpftime", event.SeverityCritical},
		{"canary name", "bpftime_canary_test", nil, "bpftime", event.SeverityCritical},
		{"renamed through env", "innocuous_cache",
			shmPtrEnv("PATH=/usr/bin", "BPFTIME_GLOBAL_SHM_NAME=innocuous_cache", "LD_PRELOAD=/x.so"),
			"bpftime", event.SeverityCritical},
		{"renamed through env with leading slash", "innocuous_cache",
			shmPtrEnv("BPFTIME_GLOBAL_SHM_NAME=/innocuous_cache"), "bpftime", event.SeverityCritical},
		{"env names another segment", "innocuous_cache",
			shmPtrEnv("BPFTIME_GLOBAL_SHM_NAME=other"), "unknown", event.SeverityInfo},
		{"env value is a prefix of the name", "innocuous_cache",
			shmPtrEnv("BPFTIME_GLOBAL_SHM_NAME=innocuous"), "unknown", event.SeverityInfo},
		{"variable name only as a value", "innocuous_cache",
			shmPtrEnv("X=BPFTIME_GLOBAL_SHM_NAME=innocuous_cache"), "unknown", event.SeverityInfo},
		{"copy cut short inside the entry", "innocuous_cache",
			[]byte("PATH=/usr/bin\x00BPFTIME_GLOBAL_SHM_NAME=innocuous_cache"), "unknown", event.SeverityInfo},
		{"empty env value", "", shmPtrEnv("BPFTIME_GLOBAL_SHM_NAME="), "unknown", event.SeverityInfo},
		{"bpf-related name", "hookmon_bpf_maps", plainEnv, "bpf_related", event.SeverityAlert},
		{"generic name", "PostgreSQL.1804289383", plainEnv, "unknown", event.SeverityInfo},
		{"generic name, no env", "sem.pulse", nil, "unknown", event.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, severity := classifySHM(tt.segment, tt.env)
			if pattern != tt.pattern || severity != tt.severity {
				t.Errorf("classifySHM(%q) = %s/%s, want %s/%s",
					tt.segment, pattern, severity, tt.pattern, tt.severity)
			}
		})
	}
}
