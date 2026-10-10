package api

import (
	"context"
	"encoding/json"
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

// PolicyReloader makes the policy engine read the allowlist and learning
// windows again. The API calls it after every write that changes them, and
// answers only after it returns, so the change applies to the next event.
type PolicyReloader interface {
	Reload(ctx context.Context) error
}

// SetPolicyReloader sets what reloads the policy after a write.
func (s *Server) SetPolicyReloader(r PolicyReloader) { s.reloader = r }

// reload applies a policy write. It reports false, having answered the
// request, when the write was saved but could not be applied.
func (s *Server) reload(w http.ResponseWriter, r *http.Request) bool {
	if s.reloader == nil {
		return true
	}
	if err := s.reloader.Reload(r.Context()); err != nil {
		s.logger.Error("policy reload after API write failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "saved, but reloading the policy failed; send SIGHUP to retry")
		return false
	}
	return true
}

// handleListPolicies lists allowlist entries. Without ?status it lists the
// entries in force (APPROVED and REJECTED). ?status=PENDING lists the
// learning-mode candidates, and ?status=ALL every entry. Statuses can be
// combined with commas.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	statuses := []event.EntryStatus{event.StatusApproved, event.StatusRejected}
	if q := r.URL.Query().Get("status"); q != "" {
		statuses = nil
		all := false
		for _, v := range strings.Split(q, ",") {
			switch st := event.EntryStatus(strings.ToUpper(strings.TrimSpace(v))); st {
			case "ALL":
				all = true
			case event.StatusApproved, event.StatusPending, event.StatusRejected:
				statuses = append(statuses, st)
			default:
				writeError(w, http.StatusBadRequest, "status must be APPROVED, PENDING, REJECTED or ALL")
				return
			}
		}
		if all {
			statuses = nil // no filter
		}
	}
	entries, err := s.store.QueryAllowlist(r.Context(), statuses...)
	if err != nil {
		s.logger.Error("query allowlist failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if entries == nil {
		entries = []*event.AllowlistEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var entry event.AllowlistEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Entries written through the API are in force at once. PENDING entries
	// come only from learning mode.
	if entry.Status != "" && entry.Status != event.StatusApproved {
		writeError(w, http.StatusBadRequest, "status must be empty or APPROVED; PENDING entries come from learning mode")
		return
	}
	if entry.Learned != nil {
		writeError(w, http.StatusBadRequest, "learned is set by learning mode only")
		return
	}
	if err := allowlist.Normalize(&entry); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry.Status = event.StatusApproved

	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	if err := s.store.CreateAllowlistEntry(r.Context(), &entry); err != nil {
		s.logger.Error("create allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}
	if !s.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteAllowlistEntry(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.logger.Error("delete allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	if !s.reload(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scopeRequest is the body of approve and reject: {"scope": "fleet"}, or
// {"scope": "host", "host_id": "<enrolled host ID>"}.
type scopeRequest struct {
	Scope  string `json:"scope"`
	HostID string `json:"host_id"`
}

// hostScope reads a scopeRequest and returns the host ID it names, "" for
// the fleet. It answers the request itself when the body is invalid.
func (s *Server) hostScope(w http.ResponseWriter, r *http.Request, req scopeRequest) (string, bool) {
	switch req.Scope {
	case "fleet":
		if req.HostID != "" {
			writeError(w, http.StatusBadRequest, `scope "fleet" takes no host_id`)
			return "", false
		}
		return "", true
	case "host":
		if req.HostID == "" {
			writeError(w, http.StatusBadRequest, `scope "host" needs host_id`)
			return "", false
		}
		if _, err := s.store.GetHost(r.Context(), req.HostID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, fmt.Sprintf("host %s is not enrolled", req.HostID))
			} else {
				s.logger.Error("look up host failed", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
			return "", false
		}
		return req.HostID, true
	}
	writeError(w, http.StatusBadRequest, `scope must be "fleet" or "host"`)
	return "", false
}

func (s *Server) handleApprovePolicy(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, event.StatusApproved)
}

func (s *Server) handleRejectPolicy(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, event.StatusRejected)
}

// decide approves or rejects a PENDING entry, for the fleet or one host.
func (s *Server) decide(w http.ResponseWriter, r *http.Request, decision event.EntryStatus) {
	var req scopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, `invalid request body: want {"scope": "fleet"} or {"scope": "host", "host_id": "..."}`)
		return
	}
	hostID, ok := s.hostScope(w, r, req)
	if !ok {
		return
	}
	entry, err := s.store.DecideCandidate(r.Context(), chi.URLParam(r, "id"), decision, hostID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return
	case errors.Is(err, store.ErrNotPending):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.logger.Error("decide allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !s.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// writeError writes {"error": msg} with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
