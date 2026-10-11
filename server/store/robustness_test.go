package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// robHost enrolls a host for the tests below.
func robHost(t *testing.T, s *Store, id string, lastHeartbeat time.Time) {
	t.Helper()
	h := &event.Host{ID: id, Hostname: "rob-" + id, Status: event.HostOnline,
		EnrolledAt: lastHeartbeat, LastHeartbeat: lastHeartbeat}
	if err := s.EnrollHost(context.Background(), h, "rob", ""); err != nil {
		t.Fatalf("EnrollHost: %v", err)
	}
}

// TestGetters_NotFoundIsErrNotFound: every single-row getter the API maps
// to 404 returns ErrNotFound (wrapped) for a missing row, and only then.
// Before step 7f, GetEvent returned a plain error, so the API answered 404
// for a database failure too.
func TestGetters_NotFoundIsErrNotFound(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()

	if _, err := s.GetEvent(ctx, "no-such-event"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetEvent of a missing event: %v, want ErrNotFound", err)
	}
	if _, err := s.GetHost(ctx, "no-such-host"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetHost of a missing host: %v, want ErrNotFound", err)
	}
	if _, err := s.GetAllowlistEntry(ctx, "no-such-entry"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAllowlistEntry of a missing entry: %v, want ErrNotFound", err)
	}
	hb := &event.HostHeartbeat{HostID: "no-such-host", ReceivedAt: time.Now().UTC()}
	if err := s.UpdateHostHeartbeat(ctx, hb); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateHostHeartbeat of a missing host: %v, want ErrNotFound", err)
	}

	// A present row is found; a closed pool is a failure, not ErrNotFound.
	evt := &event.HookEvent{ID: "rob-evt", Timestamp: time.Now().UTC(), HostID: "h", EventType: event.EventBPFLoad}
	if err := s.InsertEvent(ctx, evt); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetEvent(ctx, "rob-evt"); err != nil || got.ID != "rob-evt" {
		t.Fatalf("GetEvent: %+v, %v", got, err)
	}
	s.Close()
	if _, err := s.GetEvent(ctx, "rob-evt"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("GetEvent on a closed pool: %v, want a failure that is not ErrNotFound", err)
	}
	if _, err := s.GetHost(ctx, "no-such-host"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("GetHost on a closed pool: %v, want a failure that is not ErrNotFound", err)
	}
}

// TestRecordHeartbeat_ReportsPreviousStatus: a heartbeat returns the
// status and heartbeat time it replaced, so the server can tell a host
// coming back from UNRESPONSIVE.
func TestRecordHeartbeat_ReportsPreviousStatus(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	first := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	robHost(t, s, "h1", first)

	marked, err := s.MarkHostUnresponsive(ctx, "h1", time.Now().UTC().Add(-30*time.Second))
	if err != nil || !marked {
		t.Fatalf("MarkHostUnresponsive: %v %v", marked, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	change, err := s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "h1", ReceivedAt: now, AgentVersion: "v2",
		Sensors: []event.SensorHealth{{Name: "bpf_syscall", Status: "alive"}}})
	if err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	if change.PrevStatus != event.HostUnresponsive || !change.PrevHeartbeat.Equal(first) {
		t.Errorf("change: %+v, want UNRESPONSIVE at %v", change, first)
	}
	h, err := s.GetHost(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != event.HostOnline || !h.LastHeartbeat.Equal(now) || h.AgentVersion != "v2" || len(h.Sensors) != 1 {
		t.Errorf("host after heartbeat: %+v", h)
	}

	change, err = s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "h1", ReceivedAt: now.Add(time.Second)})
	if err != nil || change.PrevStatus != event.HostOnline || !change.PrevHeartbeat.Equal(now) {
		t.Errorf("second heartbeat: %+v %v, want ONLINE at %v", change, err, now)
	}
	if h, _ := s.GetHost(ctx, "h1"); h.AgentVersion != "v2" {
		t.Errorf("an empty agent version replaced the stored one: %q", h.AgentVersion)
	}
}

// TestRecordHeartbeat_ConcurrentReportsRecoveryOnce: many heartbeats for
// an UNRESPONSIVE host at once (two streams with the same certificate, or
// a burst after a reconnect) see UNRESPONSIVE exactly once between them.
func TestRecordHeartbeat_ConcurrentReportsRecoveryOnce(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	robHost(t, s, "h2", time.Now().UTC().Add(-time.Minute))
	if marked, err := s.MarkHostUnresponsive(ctx, "h2", time.Now().UTC()); err != nil || !marked {
		t.Fatalf("MarkHostUnresponsive: %v %v", marked, err)
	}

	const n = 16
	var wg sync.WaitGroup
	prev := make(chan event.HostStatus, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.RecordHeartbeat(ctx, &event.HostHeartbeat{HostID: "h2", ReceivedAt: time.Now().UTC()})
			if err != nil {
				t.Error(err)
				return
			}
			prev <- c.PrevStatus
		}()
	}
	wg.Wait()
	close(prev)
	unresponsive := 0
	for st := range prev {
		if st == event.HostUnresponsive {
			unresponsive++
		}
	}
	if unresponsive != 1 {
		t.Errorf("heartbeats that saw UNRESPONSIVE: %d, want 1", unresponsive)
	}
}
