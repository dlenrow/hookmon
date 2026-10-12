package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/store"
)

// Store is the interface this package requires from the storage layer.
type Store interface {
	InsertEvent(ctx context.Context, evt *event.HookEvent) error
	QueryEvents(ctx context.Context, filter store.EventFilter) ([]*event.HookEvent, error)
	GetEvent(ctx context.Context, id string) (*event.HookEvent, error)
	// QueryAllowlist returns the entries with any of the statuses, or every
	// entry when none is given.
	QueryAllowlist(ctx context.Context, statuses ...event.EntryStatus) ([]*event.AllowlistEntry, error)
	// GetAllowlistEntry returns one entry by ID.
	GetAllowlistEntry(ctx context.Context, id string) (*event.AllowlistEntry, error)
	CreateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error
	// UpdateAllowlistEntry writes an entry's editable fields;
	// store.ErrPending if the entry is a PENDING candidate.
	UpdateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error
	// GetEvent, GetHost, GetAllowlistEntry, DeleteAllowlistEntry and the
	// calls below return store.ErrNotFound (wrapped) for a missing row; any
	// other error is a store failure (500).
	DeleteAllowlistEntry(ctx context.Context, id string) error
	// DecideCandidate approves or rejects a PENDING entry for the fleet
	// (hostID "") or one host; store.ErrNotPending if it is not PENDING.
	DecideCandidate(ctx context.Context, id string, decision event.EntryStatus, hostID string) (*event.AllowlistEntry, error)
	// DecideCandidates decides several PENDING entries in one transaction,
	// for the fleet (store.ScopeFleet) or the hosts each was seen on
	// (store.ScopeSeenHosts). Per-ID failures are in the results; an error
	// means nothing changed.
	DecideCandidates(ctx context.Context, ids []string, decision event.EntryStatus, scope string) ([]store.CandidateDecision, error)
	GetLearningWindows(ctx context.Context) ([]event.LearningWindow, error)
	SetLearningWindow(ctx context.Context, w event.LearningWindow) error
	DeleteLearningWindow(ctx context.Context, hostID string) error
	GetHosts(ctx context.Context) ([]*event.Host, error)
	GetHost(ctx context.Context, id string) (*event.Host, error)
}

// handleListEvents lists stored events, newest first. A query parameter
// that is present but cannot be read (limit or offset not a non-negative
// integer, since or until not an RFC 3339 time) is a 400 naming it, never
// silently dropped: a dropped time bound returns events outside the range
// the caller asked for.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, err := intParam(q, "limit", 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := intParam(q, "offset", 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filter := store.EventFilter{
		Limit:  limit,
		Offset: offset,
		HostID: q.Get("host_id"),
	}

	if et := q.Get("event_type"); et != "" {
		t := event.EventType(et)
		filter.EventType = &t
	}
	if sev := q.Get("severity"); sev != "" {
		sv := event.Severity(sev)
		filter.Severity = &sv
	}
	if filter.Since, err = timeParam(q, "since"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if filter.Until, err = timeParam(q, "until"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	events, err := s.store.QueryEvents(r.Context(), filter)
	if err != nil {
		s.logger.Error("query events failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if events == nil {
		events = []*event.HookEvent{}
	}

	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	evt, err := s.store.GetEvent(r.Context(), id)
	if err != nil {
		s.storeError(w, "get event", err)
		return
	}
	writeJSON(w, http.StatusOK, evt)
}

// storeError answers a failed single-row store read: 404 when the row does
// not exist (store.ErrNotFound), and 500 for anything else, such as the
// database being unreachable, so an outage is never reported as a missing
// record.
func (s *Server) storeError(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.logger.Error(what+" failed", zap.Error(err))
	writeError(w, http.StatusInternalServerError, "internal server error")
}

// intParam reads the query parameter name as a non-negative integer. A
// missing or empty parameter is def; any other value that is not a
// non-negative integer is an error naming the parameter.
func intParam(q url.Values, name string, def int) (int, error) {
	raw := q.Get(name)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, not %q", name, raw)
	}
	return v, nil
}

// timeParam reads the query parameter name as an RFC 3339 time. A missing
// or empty parameter is nil; a value that does not parse is an error naming
// the parameter.
func timeParam(q url.Values, name string) (*time.Time, error) {
	raw := q.Get(name)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		msg := fmt.Sprintf("%s must be an RFC 3339 time such as 2026-10-11T00:00:00Z, not %q", name, raw)
		if strings.Contains(raw, " ") {
			// A "+" in a query string decodes to a space.
			msg += "; write a + in the UTC offset as %2B"
		}
		return nil, errors.New(msg)
	}
	return &t, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // error messages show <placeholders> as written
	enc.Encode(v)
}
