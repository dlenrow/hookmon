package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/store"
)

// allowlistEventRequest is the body of POST /api/v1/events/{id}/allowlist:
// {"scope": "fleet"} or {"scope": "host"}. With scope "host" the entry is
// for the event's host; host_id may name it but cannot name another.
type allowlistEventRequest struct {
	Scope       string `json:"scope"`
	HostID      string `json:"host_id"`
	Description string `json:"description"`
}

// EntryForEvent returns an APPROVED ALLOW entry that matches exactly the
// events with evt's learning-mode key (allowlist.KeyOf: event type, exe
// hash, subject such as the BPF tag or library hash, and container
// context), for the fleet (hostID "") or one host. It is the entry learning
// mode would have proposed for the event, approved. The key is the only
// criterion, as for learned entries: the field criteria cannot express some
// subjects (a shared-memory pattern, a linker config file), and an empty
// exe hash would match any binary.
func EntryForEvent(evt *event.HookEvent, hostID, description string, now time.Time) *event.AllowlistEntry {
	k := allowlist.KeyOf(evt)
	if description == "" {
		description = fmt.Sprintf("from event %s: %s", evt.ID, strings.TrimPrefix(allowlist.Describe(k, evt.ExePath), "learned: "))
	}
	return &event.AllowlistEntry{
		ID:          uuid.New().String(),
		CreatedAt:   now,
		CreatedBy:   "api",
		Description: description,
		EventTypes:  []event.EventType{evt.EventType},
		HostID:      hostID,
		Action:      event.ActionAllow,
		Enabled:     true,
		Status:      event.StatusApproved,
		Learned: &event.Learned{
			Key:         k,
			ExePath:     evt.ExePath,
			Occurrences: 1,
			FirstSeen:   evt.Timestamp,
			LastSeen:    evt.Timestamp,
			Hosts:       []string{evt.HostID},
		},
	}
}

// handleAllowlistEvent creates an allowlist entry from a stored event
// ("Allowlist this event" in the dashboard). See EntryForEvent. When an
// enabled ALLOW entry for the same key and scope exists, it answers 409
// with that entry's ID.
func (s *Server) handleAllowlistEvent(w http.ResponseWriter, r *http.Request) {
	var req allowlistEventRequest
	if !decodeBody(w, r, &req, true, `invalid request body: want {"scope": "fleet"} or {"scope": "host"}`) {
		return
	}
	id := chi.URLParam(r, "id")
	evt, err := s.store.GetEvent(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "event not found")
		return
	case err != nil:
		s.logger.Error("allowlist event: get event failed", zap.String("id", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	switch evt.EventType {
	case event.EventAgentOffline, event.EventAgentRecovered:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s is a host status event, not a hook; there is nothing to allowlist", evt.EventType))
		return
	}

	var hostID string
	switch req.Scope {
	case "fleet":
		if req.HostID != "" {
			writeError(w, http.StatusBadRequest, `scope "fleet" takes no host_id`)
			return
		}
	case "host":
		if evt.HostID == "" {
			writeError(w, http.StatusBadRequest, "the event has no host ID; use scope fleet")
			return
		}
		if req.HostID != "" && req.HostID != evt.HostID {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("host_id %s is not the event's host (%s)", req.HostID, evt.HostID))
			return
		}
		hostID = evt.HostID
	default:
		writeError(w, http.StatusBadRequest, `scope must be "fleet" or "host"`)
		return
	}

	now := time.Now().UTC()
	entry := EntryForEvent(evt, hostID, req.Description, now)

	existing, err := s.store.QueryAllowlist(r.Context(), event.StatusApproved)
	if err != nil {
		s.logger.Error("query allowlist failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	for _, e := range existing {
		if e.Learned != nil && e.Learned.Key == entry.Learned.Key && e.HostID == hostID &&
			e.Action == event.ActionAllow && allowlist.InForce(e, now) {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "an entry for this event's key and scope already allows it",
				"id":    e.ID,
			})
			return
		}
	}

	if err := s.store.CreateAllowlistEntry(r.Context(), entry); err != nil {
		s.logger.Error("create allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}
	if !s.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}
