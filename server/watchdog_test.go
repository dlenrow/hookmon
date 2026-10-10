package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// enrWatchdogStore is an in-memory WatchdogStore.
type enrWatchdogStore struct {
	mu     sync.Mutex
	hosts  map[string]*event.Host
	events []*event.HookEvent
}

func (s *enrWatchdogStore) GetStaleHosts(_ context.Context, threshold time.Duration) ([]*event.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-threshold)
	var out []*event.Host
	for _, h := range s.hosts {
		if h.LastHeartbeat.Before(cutoff) {
			c := *h
			out = append(out, &c)
		}
	}
	return out, nil
}

func (s *enrWatchdogStore) MarkHostUnresponsive(_ context.Context, id string, staleBefore time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hosts[id]
	if h == nil || h.Status != event.HostOnline || !h.LastHeartbeat.Before(staleBefore) {
		return false, nil
	}
	h.Status = event.HostUnresponsive
	return true, nil
}

func (s *enrWatchdogStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
	return nil
}

type enrSink struct {
	mu   sync.Mutex
	evts []*event.HookEvent
}

func (s *enrSink) Dispatch(evt *event.HookEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evts = append(s.evts, evt)
}

// TestWatchdog_OfflineOnce checks a host past the timeout gets one
// AGENT_OFFLINE event and is marked UNRESPONSIVE, a fresh host gets none,
// and a host already marked is not alerted again.
func TestWatchdog_OfflineOnce(t *testing.T) {
	now := time.Now()
	store := &enrWatchdogStore{hosts: map[string]*event.Host{
		"stale": {ID: "stale", Hostname: "web-stale", Status: event.HostOnline, LastHeartbeat: now.Add(-time.Minute)},
		"fresh": {ID: "fresh", Hostname: "web-fresh", Status: event.HostOnline, LastHeartbeat: now},
		"gone":  {ID: "gone", Hostname: "web-gone", Status: event.HostUnresponsive, LastHeartbeat: now.Add(-time.Hour)},
	}}
	sink := &enrSink{}
	w := NewWatchdog(WatchdogConfig{CheckInterval: time.Second, HeartbeatTimeout: 10 * time.Second}, store, sink, zap.NewNop())

	w.check(context.Background())
	w.check(context.Background())

	if len(store.events) != 1 {
		t.Fatalf("stored events: got %d, want 1", len(store.events))
	}
	evt := store.events[0]
	if evt.EventType != event.EventAgentOffline || evt.HostID != "stale" || evt.Hostname != "web-stale" ||
		evt.Severity != event.SeverityCritical {
		t.Errorf("offline event: %+v", evt)
	}
	if len(sink.evts) != 1 || sink.evts[0] != evt {
		t.Errorf("dispatched: %+v", sink.evts)
	}
	if store.hosts["stale"].Status != event.HostUnresponsive || store.hosts["fresh"].Status != event.HostOnline {
		t.Errorf("statuses: stale %s, fresh %s", store.hosts["stale"].Status, store.hosts["fresh"].Status)
	}
}

// TestWatchdog_HeartbeatDuringCheck has a heartbeat land after the stale
// query but before the status update. The host must stay online with no
// alert.
func TestWatchdog_HeartbeatDuringCheck(t *testing.T) {
	store := &enrRacingStore{enrWatchdogStore: enrWatchdogStore{hosts: map[string]*event.Host{
		"h": {ID: "h", Status: event.HostOnline, LastHeartbeat: time.Now().Add(-time.Minute)},
	}}}
	w := NewWatchdog(WatchdogConfig{CheckInterval: time.Second, HeartbeatTimeout: 10 * time.Second}, store, &enrSink{}, zap.NewNop())
	w.check(context.Background())
	if len(store.events) != 0 || store.hosts["h"].Status != event.HostOnline {
		t.Errorf("events %d, status %s; want no alert and ONLINE", len(store.events), store.hosts["h"].Status)
	}
}

// enrRacingStore records a heartbeat for every host right after the stale
// query returns.
type enrRacingStore struct {
	enrWatchdogStore
}

func (s *enrRacingStore) GetStaleHosts(ctx context.Context, threshold time.Duration) ([]*event.Host, error) {
	hosts, err := s.enrWatchdogStore.GetStaleHosts(ctx, threshold)
	s.mu.Lock()
	for _, h := range s.hosts {
		h.LastHeartbeat = time.Now()
	}
	s.mu.Unlock()
	return hosts, err
}
