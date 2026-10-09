package sensors

import (
	"os"
	"path/filepath"
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
	a := FileID{Dev: 1, Ino: 1, MtimeNs: 100, Mode: 0o100755}

	// Empty cache misses.
	if _, ok := cache.Get(a); ok {
		t.Fatal("expected a miss from empty cache")
	}

	// Put and get.
	detail := &event.ElfRpathDetail{HighestRisk: event.RpathRiskHigh}
	cache.Put(a, RpathResult{Detail: detail, Path: "/a"})
	if got, ok := cache.Get(a); !ok || got.Detail == nil || got.Detail.HighestRisk != event.RpathRiskHigh || got.Path != "/a" {
		t.Fatal("expected cached detail")
	}

	// Any change to the file's identity is a cache miss.
	for name, k := range map[string]FileID{
		"different mtime":  {Dev: 1, Ino: 1, MtimeNs: 200, Mode: 0o100755},
		"different inode":  {Dev: 1, Ino: 2, MtimeNs: 100, Mode: 0o100755},
		"different device": {Dev: 2, Ino: 1, MtimeNs: 100, Mode: 0o100755},
		"setuid added":     {Dev: 1, Ino: 1, MtimeNs: 100, Mode: 0o104755},
	} {
		if _, ok := cache.Get(k); ok {
			t.Errorf("%s: expected a miss", name)
		}
	}

	// Fill to capacity and verify eviction.
	cache.Put(FileID{Ino: 2}, RpathResult{Detail: detail})
	cache.Put(FileID{Ino: 3}, RpathResult{Detail: detail})
	if cache.Len() != 3 {
		t.Fatalf("expected len 3, got %d", cache.Len())
	}

	// Adding one more should evict one.
	cache.Put(FileID{Ino: 4}, RpathResult{Detail: detail})
	if cache.Len() != 3 {
		t.Fatalf("expected len 3 after eviction, got %d", cache.Len())
	}
}

// A binary without RPATH/RUNPATH is stored as a nil Detail and comes back as
// a hit, so it is not analyzed again on the next exec.
func TestRpathCacheNegative(t *testing.T) {
	cache := NewRpathCache(2)
	k := FileID{Dev: 1, Ino: 42, MtimeNs: 7}
	cache.Put(k, RpathResult{Path: "/usr/bin/true"})
	got, ok := cache.Get(k)
	if !ok {
		t.Fatal("negative result was not cached")
	}
	if got.Detail != nil {
		t.Fatalf("negative result came back with detail %+v", got.Detail)
	}
	if cache.Len() != 1 {
		t.Fatalf("len = %d, want 1", cache.Len())
	}
}

// Eviction removes the least recently used entry, where a Get counts as a
// use, and re-putting a key replaces it in place.
func TestRpathCacheLRUEviction(t *testing.T) {
	cache := NewRpathCache(3)
	k := func(i uint64) FileID { return FileID{Ino: i} }
	for i := uint64(1); i <= 3; i++ {
		cache.Put(k(i), RpathResult{Path: "v1"})
	}

	// Use 1, so 2 becomes the least recently used.
	if _, ok := cache.Get(k(1)); !ok {
		t.Fatal("1 missing")
	}
	cache.Put(k(4), RpathResult{})
	if _, ok := cache.Get(k(2)); ok {
		t.Error("2 should have been evicted as least recently used")
	}
	for _, i := range []uint64{1, 3, 4} {
		if _, ok := cache.Get(k(i)); !ok {
			t.Errorf("%d should still be cached", i)
		}
	}

	// Re-putting an existing key updates it without evicting anything.
	cache.Put(k(3), RpathResult{Path: "v2"})
	if cache.Len() != 3 {
		t.Fatalf("len = %d after re-put, want 3", cache.Len())
	}
	if got, _ := cache.Get(k(3)); got.Path != "v2" {
		t.Errorf("re-put value = %q, want v2", got.Path)
	}

	// Order now (most recent first): 3, 4, 1. Two more puts evict 1, then 4.
	cache.Put(k(5), RpathResult{})
	cache.Put(k(6), RpathResult{})
	for i, want := range map[uint64]bool{1: false, 4: false, 3: true, 5: true, 6: true} {
		if _, ok := cache.Get(k(i)); ok != want {
			t.Errorf("after two more puts: %d cached = %v, want %v", i, ok, want)
		}
	}
}

// The sensor's cache holds 10k entries and evicts the oldest past that.
func TestRpathCacheCapacity(t *testing.T) {
	cache := NewRpathCache(rpathCacheCap)
	for i := uint64(0); i <= rpathCacheCap; i++ {
		cache.Put(FileID{Ino: i}, RpathResult{})
	}
	if cache.Len() != rpathCacheCap {
		t.Fatalf("len = %d, want %d", cache.Len(), rpathCacheCap)
	}
	if _, ok := cache.Get(FileID{Ino: 0}); ok {
		t.Error("oldest entry was not evicted")
	}
	if _, ok := cache.Get(FileID{Ino: rpathCacheCap}); !ok {
		t.Error("newest entry missing")
	}
}

func TestRpathSeverity(t *testing.T) {
	cases := map[event.RpathRisk]event.Severity{
		event.RpathRiskCritical: event.SeverityCritical,
		event.RpathRiskHigh:     event.SeverityAlert,
		event.RpathRiskMedium:   event.SeverityWarn,
		event.RpathRiskLow:      event.SeverityInfo,
		event.RpathRiskNone:     event.SeverityInfo,
		"":                      event.SeverityInfo,
	}
	for risk, want := range cases {
		if got := RpathSeverity(risk); got != want {
			t.Errorf("RpathSeverity(%q) = %s, want %s", risk, got, want)
		}
	}
}

// An $ORIGIN entry is classified by the directory it resolves to.
func TestClassifyEntryOriginResolved(t *testing.T) {
	cases := []struct {
		name      string
		binaryDir string
		path      string
		want      event.RpathRisk
	}{
		{"resolves under /tmp", "/tmp/canary/bin", "$ORIGIN/../tmp", event.RpathRiskCritical},
		{"resolves to /tmp itself", "/tmp/x", "$ORIGIN/..", event.RpathRiskCritical},
		{"resolves under /home", "/home/user/app/bin", "$ORIGIN/../lib", event.RpathRiskCritical},
		{"resolves to a missing non-writable dir", "/opt/nonexistent-hookmon-test/bin", "$ORIGIN/../tmp", event.RpathRiskLow},
		{"resolves to a standard dir", "/usr/bin", "$ORIGIN/../lib", event.RpathRiskLow},
		{"prefix match is per path component", "/tmpfoo/bin", "$ORIGIN/../lib", event.RpathRiskLow},
	}
	for _, c := range cases {
		entry := classifyEntry(c.path, c.binaryDir, false, false)
		if entry.Risk != c.want {
			t.Errorf("%s: classifyEntry(%q, dir %q) = %s, want %s (%s)", c.name, c.path, c.binaryDir, entry.Risk, c.want, entry.Reason)
		}
	}

	// A world-writable directory next to the binary, like an app's scratch
	// dir: attacker-writable wherever it lives.
	base := t.TempDir()
	binDir := filepath.Join(base, "bin")
	tmpDir := filepath.Join(base, "tmp")
	for _, d := range []string{binDir, tmpDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tmpDir, 0o1777); err != nil {
		t.Fatal(err)
	}
	entry := classifyEntry("$ORIGIN/../tmp", binDir, false, false)
	want := event.RpathRiskHigh
	if dangerousPrefix(tmpDir+"/") != "" {
		want = event.RpathRiskCritical // t.TempDir() is itself under /tmp
	}
	if entry.Risk != want || !entry.Exists {
		t.Errorf("world-writable $ORIGIN/../tmp in %s: risk %s exists %v, want %s exists true (%s)",
			base, entry.Risk, entry.Exists, want, entry.Reason)
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
