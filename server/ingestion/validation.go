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

	if len(errs) > 0 {
		return fmt.Errorf("event validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}
