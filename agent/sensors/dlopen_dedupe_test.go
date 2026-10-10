package sensors

import (
	"testing"
	"time"
)

// dlopenWClock is a settable clock for dlopenDedupe.
type dlopenWClock struct{ t time.Time }

func (c *dlopenWClock) now() time.Time { return c.t }

func dlopenWNewDedupe(window time.Duration, size int) (*dlopenDedupe, *dlopenWClock) {
	c := &dlopenWClock{t: time.Unix(1_700_000_000, 0)}
	d := newDlopenDedupe(window, size)
	d.now = c.now
	return d, c
}

func TestDlopenWDedupeKey(t *testing.T) {
	d, _ := dlopenWNewDedupe(time.Hour, 16)
	steps := []struct {
		exe, lib string
		want     bool
	}{
		{"sha256:aa", "/tmp/evil.so", true},
		{"sha256:aa", "/tmp/evil.so", false}, // same binary, same library
		{"sha256:aa", "/tmp/other.so", true}, // same binary, new library
		{"sha256:bb", "/tmp/evil.so", true},  // new binary, same library
		{"sha256:aa", "/tmp/./evil.so", true},
		{"", "/tmp/evil.so", true}, // no exe hash: never suppressed
		{"", "/tmp/evil.so", true},
	}
	for i, s := range steps {
		if got := d.report(s.exe, s.lib); got != s.want {
			t.Errorf("step %d report(%q, %q) = %v, want %v", i, s.exe, s.lib, got, s.want)
		}
	}
}

func TestDlopenWDedupeWindow(t *testing.T) {
	d, c := dlopenWNewDedupe(time.Hour, 16)
	if !d.report("sha256:aa", "/x.so") {
		t.Fatal("first report suppressed")
	}
	c.t = c.t.Add(59 * time.Minute)
	if d.report("sha256:aa", "/x.so") {
		t.Fatal("repeat inside the window was reported")
	}
	// The dropped repeat at 59 min does not extend the window: the next one
	// after an hour from the first report goes out.
	c.t = c.t.Add(time.Minute)
	if !d.report("sha256:aa", "/x.so") {
		t.Fatal("repeat after the window was suppressed")
	}
	c.t = c.t.Add(time.Second)
	if d.report("sha256:aa", "/x.so") {
		t.Fatal("window did not restart at the second report")
	}
}

func TestDlopenWDedupeEvictsLeastRecent(t *testing.T) {
	d, _ := dlopenWNewDedupe(time.Hour, 2)
	d.report("sha256:aa", "/a.so")
	d.report("sha256:aa", "/b.so")
	d.report("sha256:aa", "/a.so") // a is now the most recent
	d.report("sha256:aa", "/c.so") // evicts b
	if d.report("sha256:aa", "/a.so") {
		t.Error("a was evicted; want b, the least recently seen")
	}
	if !d.report("sha256:aa", "/b.so") {
		t.Error("b was not evicted")
	}
	if n := d.order.Len(); n != 2 {
		t.Errorf("size %d, want 2", n)
	}
}
