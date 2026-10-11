package ingestion

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Validation error sentinels. Callers can use errors.Is to check for specific
// validation failures.
var (
	ErrMissingID        = errors.New("event ID is required")
	ErrMissingHostID    = errors.New("host_id is required")
	ErrMissingEventType = errors.New("event_type is required")
	ErrMissingTimestamp = errors.New("timestamp must be non-zero")

	ErrMissingInventoryDetail = errors.New("BPF_INVENTORY event requires bpf_inventory_detail with a scan_id")
	ErrMissingInventoryProg   = errors.New("BPF_INVENTORY program event requires bpf_detail with a prog_id")
	ErrMissingExecInjection   = errors.New("EXEC_INJECTION event requires exec_injection_detail naming an env_var or with scan_truncated set")

	// ErrHostStatusFromBus refuses AGENT_OFFLINE and AGENT_RECOVERED on an
	// event stream. The server raises both itself, from heartbeats (the
	// watchdog and the heartbeat handler), so each has one source and one
	// rating; a bus has no business reporting its own liveness as an event.
	ErrHostStatusFromBus = errors.New("AGENT_OFFLINE and AGENT_RECOVERED are raised by the server from heartbeats, not accepted from a bus")

	// ErrUnknownEventType refuses an event type this server cannot classify.
	ErrUnknownEventType = errors.New("unknown event_type")
)

// busEventTypes are the event types a bus may send.
var busEventTypes = map[event.EventType]bool{
	event.EventBPFLoad: true, event.EventBPFAttach: true, event.EventBPFInventory: true,
	event.EventExecInjection: true, event.EventSHMCreate: true, event.EventDlopen: true,
	event.EventLinkerConfig: true, event.EventPtraceInject: true, event.EventLibIntegrity: true,
	event.EventElfRpath: true,
}

// ValidateEvent checks that a HookEvent from a bus contains all required
// fields and is a kind of event a bus may send.
// It returns a descriptive error if any mandatory field is missing or invalid.
func ValidateEvent(evt *event.HookEvent) error {
	if evt == nil {
		return errors.New("event must not be nil")
	}

	var errs []string

	if evt.ID == "" {
		errs = append(errs, ErrMissingID.Error())
	}
	if evt.HostID == "" {
		errs = append(errs, ErrMissingHostID.Error())
	}
	if evt.EventType == "" {
		errs = append(errs, ErrMissingEventType.Error())
	}
	if evt.Timestamp.IsZero() {
		errs = append(errs, ErrMissingTimestamp.Error())
	}
	if evt.EventType == event.EventBPFInventory {
		inv := evt.BPFInventoryDetail
		switch {
		case inv == nil || inv.ScanID == "":
			errs = append(errs, ErrMissingInventoryDetail.Error())
		case !inv.Summary && (evt.BPFDetail == nil || evt.BPFDetail.ProgID == 0):
			errs = append(errs, ErrMissingInventoryProg.Error())
		}
	}
	switch {
	case evt.EventType == "" || busEventTypes[evt.EventType]:
	case evt.EventType == event.EventAgentOffline || evt.EventType == event.EventAgentRecovered:
		errs = append(errs, ErrHostStatusFromBus.Error())
	default:
		errs = append(errs, fmt.Sprintf("%v %q", ErrUnknownEventType, evt.EventType))
	}
	if evt.EventType == event.EventExecInjection {
		d := evt.ExecInjectionDetail
		if d == nil || (d.EnvVar == "" && !d.ScanTruncated) {
			errs = append(errs, ErrMissingExecInjection.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("event validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}
