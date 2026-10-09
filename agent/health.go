package agent

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/event"
)

// heartbeatMaxAge bounds how old a heartbeat may be when read right after the
// probes. The BPF side writes at most once a second, so a hook that ran for
// the probe holds a value well under this.
const heartbeatMaxAge = 5 * time.Second

// probeFilter drops events caused by the bus itself: its own bpf() calls
// (loading the sensors) and the probe children it spawns (/bin/true and the
// dlopen helper). The bus starts no other child processes, so a parent PID
// equal to the bus PID identifies a probe child. The parent PID is filled in
// by the BPF program, so this does not race the child's first event against
// the bus learning the child's PID.
type probeFilter struct {
	self uint32
}

func (f probeFilter) drop(evt *event.HookEvent) bool {
	return evt.PID == f.self || evt.PPID == f.self
}

// heartbeatProblem returns why a heartbeat value read at monotonic time now
// does not show the hook running since the previous value prev, or "" if it
// does. Values are bpf_ktime_get_ns(), i.e. CLOCK_MONOTONIC nanoseconds.
func heartbeatProblem(prev, cur, now uint64, maxAge time.Duration) string {
	switch {
	case cur == 0:
		return "heartbeat map never written"
	case cur <= prev:
		return "heartbeat did not advance since last check"
	case cur > now:
		return fmt.Sprintf("heartbeat %d is ahead of CLOCK_MONOTONIC %d", cur, now)
	case time.Duration(now-cur) > maxAge:
		return fmt.Sprintf("heartbeat is %s old", time.Duration(now-cur).Round(time.Millisecond))
	}
	return ""
}

// bpfSensor is a started eBPF sensor the health checker probes.
type bpfSensor struct {
	name   string
	health sensors.BPFHealth
}

// healthChecker runs one probe/read/evaluate cycle per tick.
type healthChecker struct {
	reg     *registry.Registry
	sensors []bpfSensor
	last    map[string]uint64

	// probe fires the hooks of the named sensors and returns, per sensor, why
	// the bus cannot test it; such sensors are reported unverifiable.
	probe func(names []string) map[string]string
	// monoNow returns CLOCK_MONOTONIC in nanoseconds.
	monoNow func() (uint64, error)
	maxAge  time.Duration
	logger  *zap.Logger
}

func newHealthChecker(reg *registry.Registry, probe func([]string) map[string]string,
	monoNow func() (uint64, error), logger *zap.Logger) *healthChecker {
	return &healthChecker{
		reg:     reg,
		last:    make(map[string]uint64),
		probe:   probe,
		monoNow: monoNow,
		maxAge:  heartbeatMaxAge,
		logger:  logger,
	}
}

func (h *healthChecker) add(name string, hb sensors.BPFHealth) {
	h.sensors = append(h.sensors, bpfSensor{name: name, health: hb})
}

// cycle fires every hook, then beats each sensor whose heartbeat moved and
// whose program is still attached, then evaluates the registry.
func (h *healthChecker) cycle() {
	names := make([]string, len(h.sensors))
	for i, s := range h.sensors {
		names[i] = s.name
	}
	unverifiable := h.probe(names)

	for _, s := range h.sensors {
		if reason := unverifiable[s.name]; reason != "" {
			h.reg.Unverifiable(s.name, reason)
			continue
		}
		cur, err := s.health.HeartbeatNs()
		if err != nil {
			h.miss(s.name, "read heartbeat map: "+err.Error())
			continue
		}
		// Read the clock after the map: reading a map is itself a bpf() call
		// that can move bpf_syscall's heartbeat forward.
		now, err := h.monoNow()
		if err != nil {
			h.miss(s.name, "read CLOCK_MONOTONIC: "+err.Error())
			continue
		}
		prev := h.last[s.name]
		h.last[s.name] = cur
		if reason := heartbeatProblem(prev, cur, now, h.maxAge); reason != "" {
			h.miss(s.name, reason)
			continue
		}
		if err := s.health.CheckAttached(); err != nil {
			h.miss(s.name, "attachment check: "+err.Error())
			continue
		}
		h.reg.Beat(s.name)
	}
	h.reg.Evaluate()
}

func (h *healthChecker) miss(name, reason string) {
	h.reg.Miss(name, reason)
	if h.logger != nil {
		h.logger.Warn("sensor heartbeat check failed", zap.String("sensor", name), zap.String("reason", reason))
	}
}
