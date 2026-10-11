package ingestion

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
)

// TestValidateEvent_BusEventTypes: a bus may send only the sensor event
// types. AGENT_OFFLINE and AGENT_RECOVERED are refused (the server raises
// them), and so is a type the server does not know.
func TestValidateEvent_BusEventTypes(t *testing.T) {
	for _, et := range []event.EventType{event.EventAgentOffline, event.EventAgentRecovered} {
		evt := validEvent()
		evt.EventType = et
		if err := ValidateEvent(evt); err == nil || !strings.Contains(err.Error(), ErrHostStatusFromBus.Error()) {
			t.Errorf("%s: got %v, want ErrHostStatusFromBus", et, err)
		}
	}
	evt := validEvent()
	evt.EventType = "EventType(1048576)"
	if err := ValidateEvent(evt); err == nil || !strings.Contains(err.Error(), ErrUnknownEventType.Error()) {
		t.Errorf("unknown type: got %v, want ErrUnknownEventType", err)
	}
	for et := range busEventTypes {
		evt := validEvent()
		evt.EventType = et
		evt.BPFInventoryDetail = &event.BPFInventoryDetail{ScanID: "s", Summary: true}
		evt.ExecInjectionDetail = &event.ExecInjectionDetail{EnvVar: "LD_PRELOAD"}
		if err := ValidateEvent(evt); err != nil {
			t.Errorf("%s: %v", et, err)
		}
	}
}

// TestProtoToEvent_UnspecifiedTypeIsMissing: a message without an event
// type converts to an empty type, which validation reports as missing.
// Before step 7f it became "EVENT_TYPE_UNSPECIFIED" and was stored.
func TestProtoToEvent_UnspecifiedTypeIsMissing(t *testing.T) {
	evt := protoToEvent(&hookmonv1.HookEvent{Id: "e", HostId: "h", Timestamp: timestamppb.Now()})
	if evt.EventType != "" {
		t.Errorf("event type: %q, want empty", evt.EventType)
	}
	if err := ValidateEvent(evt); err == nil || !strings.Contains(err.Error(), ErrMissingEventType.Error()) {
		t.Errorf("validation: %v, want ErrMissingEventType", err)
	}
}
