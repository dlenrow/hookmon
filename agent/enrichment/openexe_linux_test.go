//go:build linux

package enrichment

// The executable path an event names is opened without blocking, and only
// a regular file is hashed (fix plan step 7h). A FIFO swapped in at the
// path must not hang the bus.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestEnrichOnlyHashesRegularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEnricher()
	for name, path := range map[string]string{
		"FIFO":      fifo,
		"directory": dir,
		"missing":   filepath.Join(dir, "missing"),
	} {
		evt := &event.HookEvent{PID: uint32(os.Getpid()), ExePath: path}
		done := make(chan struct{})
		go func() { e.Enrich(evt); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Enrich blocked", name)
		}
		if evt.ExeHash != "" || evt.ExePath != path {
			t.Errorf("%s: ExePath %q, ExeHash %q; want the path kept and no hash", name, evt.ExePath, evt.ExeHash)
		}
		if evt.Cmdline == "" {
			t.Errorf("%s: the rest of the enrichment was skipped", name)
		}
	}
}

// A cache of size zero still holds one entry.
func TestEnrichHashCacheMinimumSize(t *testing.T) {
	c := NewHashCache(0)
	enrichOldEnough(c)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enrichHashPath(t, c, a)
	enrichHashPath(t, c, a)
	enrichHashPath(t, c, b)
	if c.order.Len() != 1 || c.hits != 1 || c.misses != 2 {
		t.Errorf("len %d hits %d misses %d; want 1, 1, 2", c.order.Len(), c.hits, c.misses)
	}
}
