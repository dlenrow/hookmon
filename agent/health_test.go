package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/pkg/event"
)

func TestProbeFilter(t *testing.T) {
	f := probeFilter{self: 1000}
	cases := []struct {
		name      string
		pid, ppid uint32
		want      bool
	}{
		{"bus itself", 1000, 1, true},
		{"probe child of the bus", 1234, 1000, true},
		{"unrelated process", 1234, 1, false},
		{"grandchild of the bus", 1300, 1234, false},
		{"pid zero", 0, 0, false},
	}
	for _, c := range cases {
		evt := &event.HookEvent{PID: c.pid, PPID: c.ppid}
		if got := f.drop(evt); got != c.want {
			t.Errorf("%s: drop(pid=%d ppid=%d) = %v, want %v", c.name, c.pid, c.ppid, got, c.want)
		}
	}
}

func TestHeartbeatProblem(t *testing.T) {
	const s = uint64(time.Second)
	cases := []struct {
		name           string
		prev, cur, now uint64
		ok             bool
	}{
		{"first write", 0, 100 * s, 100*s + 1, true},
		{"advanced and fresh", 90 * s, 100 * s, 101 * s, true},
		{"never written", 0, 0, 100 * s, false},
		{"did not advance", 100 * s, 100 * s, 110 * s, false},
		{"went backwards", 100 * s, 99 * s, 110 * s, false},
		{"ahead of the clock", 90 * s, 100 * s, 99 * s, false},
		{"advanced but stale", 90 * s, 100 * s, 106 * s, false},
	}
	for _, c := range cases {
		got := heartbeatProblem(c.prev, c.cur, c.now, 5*time.Second)
		if (got == "") != c.ok {
			t.Errorf("%s: heartbeatProblem(%d, %d, %d) = %q, want ok=%v", c.name, c.prev, c.cur, c.now, got, c.ok)
		}
	}
}

// fakeHook stands in for an eBPF sensor. Probing it writes the current time
// to its heartbeat unless it has been detached.
type fakeHook struct {
	clock     *uint64
	value     uint64
	detached  bool
	attachErr error
}

func (f *fakeHook) fire() {
	if !f.detached {
		f.value = *f.clock
	}
}
func (f *fakeHook) HeartbeatNs() (uint64, error) { return f.value, nil }
func (f *fakeHook) CheckAttached() error         { return f.attachErr }

type fakeBus struct {
	clock        uint64
	hooks        map[string]*fakeHook
	unverifiable map[string]string
	h            *healthChecker
	reg          *registry.Registry
}

func newFakeBus(threshold time.Duration, names ...string) *fakeBus {
	b := &fakeBus{clock: uint64(time.Hour), hooks: map[string]*fakeHook{}, unverifiable: map[string]string{}}
	b.reg = registry.NewWithThreshold(names, threshold)
	b.h = newHealthChecker(b.reg, func(ns []string) map[string]string {
		b.clock += uint64(time.Millisecond)
		for _, n := range ns {
			b.hooks[n].fire()
		}
		return b.unverifiable
	}, func() (uint64, error) { return b.clock, nil }, nil)
	for _, n := range names {
		b.hooks[n] = &fakeHook{clock: &b.clock}
		b.h.add(n, b.hooks[n])
	}
	return b
}

func (b *fakeBus) statuses() map[string]registry.SensorStatus {
	out := map[string]registry.SensorStatus{}
	for _, s := range b.reg.Snapshot() {
		out[s.Name] = s
	}
	return out
}

func TestHealthCycleAllAlive(t *testing.T) {
	b := newFakeBus(time.Minute, "a", "b")
	for i := 0; i < 3; i++ {
		b.h.cycle()
	}
	if got := b.reg.Overall(); got != "alive" {
		t.Fatalf("overall = %s, want alive: %+v", got, b.statuses())
	}
}

// A detached hook stops beating and goes dead once the threshold passes,
// while the others stay alive.
func TestHealthCycleDetachedHookGoesDead(t *testing.T) {
	const interval = 200 * time.Millisecond
	b := newFakeBus(interval*3/2, "a", "b")
	b.h.cycle()
	if got := b.reg.Overall(); got != "alive" {
		t.Fatalf("overall after first cycle = %s, want alive", got)
	}

	b.hooks["b"].detached = true
	deadline := time.Now().Add(5 * interval)
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		b.h.cycle()
		if b.statuses()["b"].Status == registry.StatusDead {
			break
		}
	}
	st := b.statuses()
	if st["b"].Status != registry.StatusDead {
		t.Fatalf("b = %+v, want dead", st["b"])
	}
	if st["b"].Reason == "" {
		t.Error("expected a reason on the dead sensor")
	}
	if st["a"].Status != registry.StatusAlive {
		t.Errorf("a = %+v, want alive", st["a"])
	}
	if got := b.reg.Overall(); got != "degraded" {
		t.Errorf("overall = %s, want degraded", got)
	}
}

// The attachment check is a second, independent signal: a heartbeat that
// still moves does not keep a sensor alive if its program is not attached.
func TestHealthCycleAttachmentCheckBlocksBeat(t *testing.T) {
	b := newFakeBus(time.Minute, "a")
	b.hooks["a"].attachErr = errors.New("no BPF program attached to perf event")
	b.h.cycle()
	st := b.statuses()["a"]
	if st.Status == registry.StatusAlive {
		t.Fatalf("a = %+v, want not alive", st)
	}
	if st.Reason == "" {
		t.Error("expected the attachment error as the reason")
	}
}

func TestHealthCycleUnverifiable(t *testing.T) {
	b := newFakeBus(time.Minute, "a", "dlopen_monitor")
	b.unverifiable["dlopen_monitor"] = "dlopen probe helper unavailable"
	b.h.cycle()
	st := b.statuses()
	if st["dlopen_monitor"].Status != registry.StatusUnverifiable {
		t.Fatalf("dlopen_monitor = %+v, want unverifiable", st["dlopen_monitor"])
	}
	if st["a"].Status != registry.StatusAlive {
		t.Errorf("a = %+v, want alive", st["a"])
	}
	if got := b.reg.Overall(); got == "alive" {
		t.Error("overall must not be alive with an unverifiable sensor")
	}

	// Once the helper works the sensor is checked normally again.
	delete(b.unverifiable, "dlopen_monitor")
	b.h.cycle()
	if got := b.reg.Overall(); got != "alive" {
		t.Errorf("overall after helper returns = %s, want alive", got)
	}
}
