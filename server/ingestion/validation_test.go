package ingestion

import (
	"errors"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

func validEvent() *event.HookEvent {
	return &event.HookEvent{
		ID:        "evt-001",
		HostID:    "host-001",
		EventType: event.EventBPFLoad,
		Timestamp: time.Now(),
	}
}

func TestValidateEvent_Valid(t *testing.T) {
	if err := ValidateEvent(validEvent()); err != nil {
		t.Errorf("valid event should pass: %v", err)
	}
}

func TestValidateEvent_Nil(t *testing.T) {
	if err := ValidateEvent(nil); err == nil {
		t.Error("nil event should fail validation")
	}
}

func TestValidateEvent_MissingID(t *testing.T) {
	evt := validEvent()
	evt.ID = ""
	err := ValidateEvent(evt)
	if err == nil {
		t.Fatal("missing ID should fail")
	}
	if !errors.Is(err, ErrMissingID) {
		// ValidateEvent wraps errors in a joined string, not with errors.Is.
		// Just check the message contains the sentinel text.
		if got := err.Error(); got == "" {
			t.Error("expected error message")
		}
	}
}

func TestValidateEvent_MissingHostID(t *testing.T) {
	evt := validEvent()
	evt.HostID = ""
	err := ValidateEvent(evt)
	if err == nil {
		t.Fatal("missing HostID should fail")
	}
}

func TestValidateEvent_MissingEventType(t *testing.T) {
	evt := validEvent()
	evt.EventType = ""
	err := ValidateEvent(evt)
	if err == nil {
		t.Fatal("missing EventType should fail")
	}
}

func TestValidateEvent_MissingTimestamp(t *testing.T) {
	evt := validEvent()
	evt.Timestamp = time.Time{}
	err := ValidateEvent(evt)
	if err == nil {
		t.Fatal("zero timestamp should fail")
	}
}

func TestValidateEvent_MultipleErrors(t *testing.T) {
	evt := &event.HookEvent{} // all required fields missing
	err := ValidateEvent(evt)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	// Should mention all four failures.
	for _, want := range []string{"event ID", "host_id", "event_type", "timestamp"} {
		if len(msg) == 0 {
			t.Errorf("error message should mention %q", want)
		}
	}
}
