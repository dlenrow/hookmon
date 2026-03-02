package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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
	GetAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error)
	CreateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error
	DeleteAllowlistEntry(ctx context.Context, id string) error
	GetHosts(ctx context.Context) ([]*event.Host, error)
	GetHost(ctx context.Context, id string) (*event.Host, error)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.EventFilter{
		Limit:  intParam(q.Get("limit"), 100),
		Offset: intParam(q.Get("offset"), 0),
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
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = &t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = &t
		}
	}

	events, err := s.store.QueryEvents(r.Context(), filter)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		s.logger.Error("query events failed", zap.Error(err))
		return
	}

	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	evt, err := s.store.GetEvent(r.Context(), id)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, evt)
}

func intParam(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
