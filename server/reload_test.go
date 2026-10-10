package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/policy"
)

// polSource is a policy source the test edits behind the engine's back, as
// someone editing the database directly would.
type polSource struct {
	mu      sync.Mutex
	entries []*event.AllowlistEntry
	err     error
}

func (s *polSource) GetDecidedAllowlist(context.Context) ([]*event.AllowlistEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries, s.err
}

func (s *polSource) GetLearningWindows(context.Context) ([]event.LearningWindow, error) {
	return nil, nil
}

func (s *polSource) set(entries []*event.AllowlistEntry, err error) {
	s.mu.Lock()
	s.entries, s.err = entries, err
	s.mu.Unlock()
}

func polEvent() *event.HookEvent {
	return &event.HookEvent{ID: "e", HostID: "h", EventType: event.EventBPFLoad, Severity: event.SeverityWarn, UID: 1000,
		ExeHash: "sha256:x", BPFDetail: &event.BPFDetail{ProgType: 5, ProgHash: "a04f5eef06a7f555"}}
}

// TestSIGHUPReloadsPolicy sends a real SIGHUP to the process, as `kill -HUP`
// would to hookmon-server, and checks that an allowlist change made in the
// source behind the engine's back is applied, and that a failed reload
// keeps the previous allowlist and keeps listening.
func TestSIGHUPReloadsPolicy(t *testing.T) {
	src := &polSource{}
	engine := policy.NewEngine(zap.NewNop())
	engine.SetSource(src)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	reloads := make(chan error, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reloadOnSignal(ctx, hup, func(ctx context.Context) error {
			err := engine.Reload(ctx)
			reloads <- err
			return err
		}, zap.NewNop())
	}()
	defer func() { cancel(); <-done }()

	kick := func() error {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-reloads:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("no reload within 5s of SIGHUP")
		}
		return nil
	}

	if res := engine.Evaluate(polEvent()); res.Action != event.ActionAlert {
		t.Fatalf("before: %s", res.Action)
	}
	src.set([]*event.AllowlistEntry{{ID: "allow-tag", ProgHash: "a04f5eef06a7f555", Action: event.ActionAllow, Enabled: true}}, nil)
	if res := engine.Evaluate(polEvent()); res.Action != event.ActionAlert {
		t.Fatalf("changed without a reload: %s", res.Action)
	}
	if err := kick(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if res := engine.Evaluate(polEvent()); res.Action != event.ActionAllow || res.MatchedEntryID != "allow-tag" {
		t.Fatalf("after SIGHUP: %+v", res)
	}

	src.set(nil, errors.New("database unavailable"))
	if err := kick(); err == nil {
		t.Fatal("reload against a failing source succeeded")
	}
	if res := engine.Evaluate(polEvent()); res.Action != event.ActionAllow {
		t.Errorf("a failed reload dropped the allowlist: %s", res.Action)
	}

	src.set(nil, nil)
	if err := kick(); err != nil {
		t.Fatalf("reload after recovery: %v", err)
	}
	if res := engine.Evaluate(polEvent()); res.Action != event.ActionAlert {
		t.Errorf("entry removed and SIGHUP sent, still %s", res.Action)
	}
}
