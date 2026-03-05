package sensors

import (
	"os"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestClassifyEntry(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		isRpath  bool
		isSetuid bool
		wantRisk event.RpathRisk
	}{
		{
			name:     "empty path",
			path:     "",
			wantRisk: event.RpathRiskHigh,
		},
		{
			name:     "relative path",
			path:     "lib",
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "relative path with DT_RPATH",
			path:     "lib",
			isRpath:  true,
			wantRisk: event.RpathRiskCritical, // already max
		},
		{
			name:     "tmp prefix",
			path:     "/tmp/evil",
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "var/tmp prefix",
			path:     "/var/tmp/libs",
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "dev/shm prefix",
			path:     "/dev/shm/inject",
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "home directory",
			path:     "/home/user/lib",
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "$ORIGIN non-suid",
			path:     "$ORIGIN/../lib",
			wantRisk: event.RpathRiskLow,
		},
		{
			name:     "$ORIGIN suid",
			path:     "$ORIGIN/../lib",
			isSetuid: true,
			wantRisk: event.RpathRiskCritical,
		},
		{
			name:     "$ORIGIN non-suid with DT_RPATH",
			path:     "$ORIGIN/../lib",
			isRpath:  true,
			wantRisk: event.RpathRiskMedium, // LOW bumped to MEDIUM
		},
		{
			name:     "standard system path /usr/lib",
			path:     "/usr/lib",
			wantRisk: event.RpathRiskNone,
		},
		{
			name:     "standard system path /usr/lib64",
			path:     "/usr/lib64",
			wantRisk: event.RpathRiskNone,
		},
		{
			name:     "standard system path with DT_RPATH",
			path:     "/usr/lib",
			isRpath:  true,
			wantRisk: event.RpathRiskLow, // NONE bumped to LOW
		},
		{
			name:     "non-existent directory",
			path:     "/opt/nonexistent/lib123456",
			wantRisk: event.RpathRiskHigh,
		},
		{
			name:     "non-existent with DT_RPATH",
			path:     "/opt/nonexistent/lib123456",
			isRpath:  true,
			wantRisk: event.RpathRiskCritical, // HIGH bumped to CRITICAL
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := classifyEntry(tt.path, "/usr/bin", tt.isRpath, tt.isSetuid)
			if entry.Risk != tt.wantRisk {
				t.Errorf("classifyEntry(%q, isRpath=%v, isSetuid=%v) risk = %q, want %q (reason: %s)",
					tt.path, tt.isRpath, tt.isSetuid, entry.Risk, tt.wantRisk, entry.Reason)
			}
		})
	}
}

func TestRpathCache(t *testing.T) {
	cache := NewRpathCache(3)

	// Empty cache returns nil.
	if got := cache.Get("/a", 1, 100); got != nil {
		t.Fatal("expected nil from empty cache")
	}

	// Put and get.
	detail := &event.ElfRpathDetail{HighestRisk: event.RpathRiskHigh}
	cache.Put("/a", 1, 100, detail)
	if got := cache.Get("/a", 1, 100); got == nil || got.HighestRisk != event.RpathRiskHigh {
		t.Fatal("expected cached detail")
	}

	// Different mtime = cache miss.
	if got := cache.Get("/a", 1, 200); got != nil {
		t.Fatal("expected nil for different mtime")
	}

	// Fill to capacity and verify eviction.
	cache.Put("/b", 2, 100, detail)
	cache.Put("/c", 3, 100, detail)
	if cache.Len() != 3 {
		t.Fatalf("expected len 3, got %d", cache.Len())
	}

	// Adding one more should evict one.
	cache.Put("/d", 4, 100, detail)
	if cache.Len() != 3 {
		t.Fatalf("expected len 3 after eviction, got %d", cache.Len())
	}
}

func TestAnalyzeElfRpath_NonELF(t *testing.T) {
	// Analyze a non-ELF file — should return nil, nil.
	tmpfile, err := os.CreateTemp("", "not-elf-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.WriteString("this is not an elf file")
	tmpfile.Close()

	detail, err := AnalyzeElfRpath(tmpfile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail != nil {
		t.Fatal("expected nil detail for non-ELF file")
	}
}

func TestAnalyzeElfRpath_SystemBinary(t *testing.T) {
	// Analyze /bin/sh or /usr/bin/env — should work without error.
	// Most system binaries don't have RPATH, so detail should be nil.
	paths := []string{"/bin/sh", "/usr/bin/env", "/bin/ls"}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		detail, err := AnalyzeElfRpath(p)
		if err != nil {
			t.Errorf("AnalyzeElfRpath(%s) error: %v", p, err)
		}
		// We don't check detail content — most system binaries won't have RPATH.
		_ = detail
		return // Found at least one system binary to test.
	}
	t.Skip("no system binary found for test")
}

func TestRiskLevel(t *testing.T) {
	if riskLevel(event.RpathRiskNone) >= riskLevel(event.RpathRiskLow) {
		t.Error("NONE should be less than LOW")
	}
	if riskLevel(event.RpathRiskLow) >= riskLevel(event.RpathRiskMedium) {
		t.Error("LOW should be less than MEDIUM")
	}
	if riskLevel(event.RpathRiskMedium) >= riskLevel(event.RpathRiskHigh) {
		t.Error("MEDIUM should be less than HIGH")
	}
	if riskLevel(event.RpathRiskHigh) >= riskLevel(event.RpathRiskCritical) {
		t.Error("HIGH should be less than CRITICAL")
	}
}
