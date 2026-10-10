//go:build linux

package sensors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/enrichment"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Each binary version is reported once, on its first exec: later execs of
// the same version produce no event, a new version does.
func TestRpathWEmitOncePerBinaryVersion(t *testing.T) {
	s := NewElfRpathSensor()
	path := filepath.Join(t.TempDir(), "tool")
	rpathWWriteELF(t, path, "/tmp/evil")

	raw := execRecord(t, path, path, noSuchPID, noSuchPID)
	first := s.handleExec(raw)
	if first == nil {
		t.Fatal("first exec of a binary with RUNPATH /tmp/evil produced no event")
	}
	if first.Severity != event.SeverityCritical || first.ElfRpathDetail.HighestRisk != event.RpathRiskCritical {
		t.Errorf("severity %s risk %s, want CRITICAL", first.Severity, first.ElfRpathDetail.HighestRisk)
	}
	if want := realPath(path); first.ExePath != want {
		t.Errorf("ExePath = %q, want %q", first.ExePath, want)
	}
	// The hash is of the file the kernel loaded, in the one format.
	if want := enrichment.SHA256File(path); first.ExeHash != want {
		t.Errorf("ExeHash = %q, want %q", first.ExeHash, want)
	}

	for i := 0; i < 3; i++ {
		if evt := s.handleExec(raw); evt != nil {
			t.Fatalf("exec %d of the same binary version produced another event", i+2)
		}
	}

	// A new version (mtime changed) is analyzed again and reported once.
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	raw2 := execRecord(t, path, path, noSuchPID, noSuchPID)
	if s.handleExec(raw2) == nil {
		t.Fatal("new version of the binary was not reported")
	}
	if s.handleExec(raw2) != nil {
		t.Fatal("new version reported twice")
	}
}

// An event the sensor could not deliver is reported on the next exec of
// the binary, from the cached analysis.
func TestRpathWUndeliveredEventReportedAgain(t *testing.T) {
	s := NewElfRpathSensor()
	path := filepath.Join(t.TempDir(), "tool")
	rpathWWriteELF(t, path, "/var/tmp/x")
	raw := execRecord(t, path, path, noSuchPID, noSuchPID)
	if s.handleExec(raw) == nil {
		t.Fatal("no event on first exec")
	}
	s.cache.unclaimEmit(execFileID(raw)) // what readLoop does when the channel is full
	evt := s.handleExec(raw)
	if evt == nil {
		t.Fatal("undelivered event was not reported on the next exec")
	}
	if want := enrichment.SHA256File(path); evt.ExeHash != want {
		t.Errorf("ExeHash = %q, want %q", evt.ExeHash, want)
	}
	if s.handleExec(raw) != nil {
		t.Fatal("reported again after delivery")
	}
}

// A binary whose only non-standard RUNPATH directory is root-only-writable
// ranks LOW: analyzed and cached, never reported.
func TestRpathWRootOnlyRunpathNoEvent(t *testing.T) {
	if !rpathWRootOnly(t, "/usr/bin") {
		t.Skip("/usr/bin is not root-only-writable here")
	}
	s := NewElfRpathSensor()
	path := filepath.Join(t.TempDir(), "tool")
	rpathWWriteELF(t, path, "/usr/bin")
	raw := execRecord(t, path, path, noSuchPID, noSuchPID)
	if evt := s.handleExec(raw); evt != nil {
		t.Fatalf("event for a root-only RUNPATH: risk %s", evt.ElfRpathDetail.HighestRisk)
	}
	res, ok := s.cache.Get(execFileID(raw))
	if !ok || res.Detail == nil || res.Detail.HighestRisk != event.RpathRiskLow {
		t.Fatalf("cached analysis = %+v, %v; want LOW", res.Detail, ok)
	}
}
