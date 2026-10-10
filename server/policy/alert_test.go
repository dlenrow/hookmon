package policy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

func siemAlertEvt(host, exe, tag string) *event.HookEvent {
	return &event.HookEvent{
		HostID: host, EventType: event.EventBPFLoad, Severity: event.SeverityCritical,
		ExePath: exe, ExeHash: "sha256:" + "aa",
		BPFDetail: &event.BPFDetail{ProgType: 2, ProgName: "p", ProgHash: tag},
	}
}

// TestAlertManager_Admit: a repeat within the window is suppressed; the
// same alert on another host, from another binary, or for another BPF
// program is not; after the window it is admitted again.
func TestAlertManager_Admit(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	am := NewAlertManager(zap.NewNop(), 5*time.Minute)
	am.now = func() time.Time { return now }

	base := siemAlertEvt("h1", "/usr/bin/loader", "a04f5eef06a7f555")
	if !am.Admit(base) {
		t.Fatal("first alert not admitted")
	}
	if am.Admit(siemAlertEvt("h1", "/usr/bin/loader", "a04f5eef06a7f555")) {
		t.Error("repeat within the window admitted")
	}
	for name, e := range map[string]*event.HookEvent{
		"other host":    siemAlertEvt("h2", "/usr/bin/loader", "a04f5eef06a7f555"),
		"other binary":  siemAlertEvt("h1", "/usr/bin/other", "a04f5eef06a7f555"),
		"other program": siemAlertEvt("h1", "/usr/bin/loader", "1111111111111111"),
	} {
		if !am.Admit(e) {
			t.Errorf("%s suppressed", name)
		}
	}

	now = now.Add(4 * time.Minute)
	if am.Admit(siemAlertEvt("h1", "/usr/bin/loader", "a04f5eef06a7f555")) {
		t.Error("repeat at 4m admitted")
	}
	now = now.Add(time.Minute + time.Second)
	if !am.Admit(siemAlertEvt("h1", "/usr/bin/loader", "a04f5eef06a7f555")) {
		t.Error("alert after the window suppressed")
	}
	if base.PolicyResult != nil {
		t.Error("Admit changed the event")
	}

	// Old keys are pruned.
	now = now.Add(time.Hour)
	am.Admit(siemAlertEvt("h9", "/x", "2222222222222222"))
	am.mu.Lock()
	n := len(am.recent)
	am.mu.Unlock()
	if n != 1 {
		t.Errorf("%d keys after an hour, want 1", n)
	}
}

// TestAlertManager_ConcurrentAdmitOnce: streams racing with the same alert
// admit it once.
func TestAlertManager_ConcurrentAdmitOnce(t *testing.T) {
	am := NewAlertManager(zap.NewNop(), time.Minute)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if am.Admit(siemAlertEvt("h", "/bin/x", "a04f5eef06a7f555")) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Errorf("admitted %d times, want 1", admitted.Load())
	}
}
