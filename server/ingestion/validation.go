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
)

// ValidateEvent checks that a HookEvent contains all required fields.
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

	if len(errs) > 0 {
		return fmt.Errorf("event validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}
