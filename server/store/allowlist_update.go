package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dlenrow/hookmon/pkg/event"
)

// ErrPending is returned when editing an entry that is a PENDING candidate;
// those are approved or rejected, not edited.
var ErrPending = errors.New("allowlist entry is PENDING: approve or reject it first")

// UpdateAllowlistEntry writes an entry's editable fields: description,
// match criteria, host scope, action, expiry and enabled. The ID, creation
// fields, status and learning-mode record are left as they are. It returns
// ErrNotFound for a missing entry and ErrPending for a PENDING one.
func (s *Store) UpdateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error {
	eventTypesJSON := []byte("[]")
	if entry.EventTypes != nil {
		var err error
		if eventTypesJSON, err = json.Marshal(entry.EventTypes); err != nil {
			return fmt.Errorf("marshal event_types: %w", err)
		}
	}
	uidRangeJSON, err := nullableJSON(entry.UIDRange)
	if err != nil {
		return fmt.Errorf("marshal uid_range: %w", err)
	}
	var allowedRpathsJSON []byte
	if len(entry.AllowedRpaths) > 0 {
		if allowedRpathsJSON, err = json.Marshal(entry.AllowedRpaths); err != nil {
			return fmt.Errorf("marshal allowed_rpaths: %w", err)
		}
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE allowlist SET
			description = $2,
			event_types = $3, exe_hash = $4, exe_path = $5,
			library_hash = $6, library_path = $7,
			prog_name = $8, prog_type = $9, prog_hash = $10, host_pattern = $11,
			uid_range = $12, container_image = $13,
			allowed_rpaths = $14, host_id = $15,
			action = $16, expires = $17, enabled = $18
		WHERE id = $1 AND status <> 'PENDING'`,
		entry.ID,
		entry.Description,
		eventTypesJSON, entry.ExeHash, entry.ExePath,
		entry.LibraryHash, entry.LibraryPath,
		entry.ProgName, entry.ProgType, entry.ProgHash, entry.HostPattern,
		uidRangeJSON, entry.ContainerImage,
		allowedRpathsJSON, entry.HostID,
		string(entry.Action), entry.Expires, entry.Enabled,
	)
	if err != nil {
		return fmt.Errorf("update allowlist entry %s: %w", entry.ID, err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	cur, err := s.GetAllowlistEntry(ctx, entry.ID)
	if err != nil {
		return err
	}
	if cur.Status == event.StatusPending {
		return fmt.Errorf("allowlist entry %s: %w", entry.ID, ErrPending)
	}
	return fmt.Errorf("update allowlist entry %s: no row changed", entry.ID)
}
