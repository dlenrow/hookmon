package agent

import (
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/registry"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/event"
)

// goHealthSensor is a Go-side sensor whose health the test sets.
type goHealthSensor struct{ health error }

func (s *goHealthSensor) Name() string                    { return "linker_config" }
func (s *goHealthSensor) Type() sensors.SensorType        { return sensors.SensorTypeFanotify }
func (s *goHealthSensor) Start() error                    { return nil }
func (s *goHealthSensor) Stop() error                     { return nil }
func (s *goHealthSensor) Events() <-chan *event.HookEvent { return nil }
func (s *goHealthSensor) Healthy() error                  { return s.health }

func goHealthStatus(t *testing.T, r *registry.Registry) registry.SensorStatus {
	t.Helper()
	for _, st := range r.Snapshot() {
		if st.Name == "linker_config" {
			return st
		}
	}
	t.Fatal("linker_config not registered")
	return registry.SensorStatus{}
}

// A fanotify sensor whose reads keep failing must not keep beating: its
// ticker records the reason and leaves the last beat alone, so the
// registry declares it dead once the threshold passes.
func TestBeatGoSensorSkipsUnhealthy(t *testing.T) {
	reg := registry.New([]string{"linker_config"})
	a := &Agent{logger: zap.NewNop(), registry: reg}
	s := &goHealthSensor{}

	a.beatGoSensor(s)
	first := goHealthStatus(t, reg)
	if first.LastBeat.IsZero() {
		t.Fatal("healthy sensor did not beat")
	}

	time.Sleep(10 * time.Millisecond)
	s.health = errors.New("fanotify read failing (3 errors in a row): EIO")
	a.beatGoSensor(s)
	after := goHealthStatus(t, reg)
	if !after.LastBeat.Equal(first.LastBeat) {
		t.Error("unhealthy sensor beat")
	}
	if after.Reason != s.health.Error() {
		t.Errorf("reason = %q, want %q", after.Reason, s.health.Error())
	}
}
