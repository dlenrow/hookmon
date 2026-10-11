package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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

// validateEntry checks the parts of an entry an operator writes: the action
// and the hash formats, which it normalizes. A REJECTED entry exists to keep
// an event alerting, so its action stays ALERT.
func validateEntry(e *event.AllowlistEntry) error {
	switch e.Action {
	case event.ActionAllow, event.ActionAlert, event.ActionDeny:
	default:
		return fmt.Errorf("action must be ALLOW, ALERT or DENY, not %q", e.Action)
	}
	if e.Status == event.StatusRejected && e.Action != event.ActionAlert {
		return errors.New("a REJECTED entry keeps action ALERT; delete it instead")
	}
	return allowlist.Normalize(e)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var entry event.AllowlistEntry
	if !decodeBody(w, r, &entry, true, "invalid request body") {
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
	entry.Status = event.StatusApproved
	if err := validateEntry(&entry); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

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

// editableFields are the entry fields PUT replaces and PATCH may set. The
// rest (id, created_at, created_by, status, learned) belong to the server.
var editableFields = map[string]bool{
	"description": true, "event_types": true,
	"exe_hash": true, "exe_path": true,
	"library_hash": true, "library_path": true,
	"prog_name": true, "prog_type": true, "prog_hash": true,
	"host_pattern": true, "uid_range": true, "container_image": true,
	"allowed_rpaths": true, "host_id": true,
	"action": true, "expires": true, "enabled": true,
}

// editableEntry loads the entry a PUT or PATCH names. It answers the
// request itself (404, 409 for a PENDING candidate, 500) and returns false
// when the entry cannot be edited.
func (s *Server) editableEntry(w http.ResponseWriter, r *http.Request, id string) (*event.AllowlistEntry, bool) {
	cur, err := s.store.GetAllowlistEntry(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	case err != nil:
		s.logger.Error("get allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return nil, false
	case cur.Status == event.StatusPending:
		writeError(w, http.StatusConflict, fmt.Sprintf("entry %s is PENDING: approve or reject it first", id))
		return nil, false
	}
	return cur, true
}

// handleReplacePolicy replaces an entry's criteria, action, expiry,
// description and enabled flag (PUT). The body is a whole entry, such as
// one from GET with fields changed; omitted fields become empty. The id,
// created_at, created_by and learned fields are kept from the stored entry,
// and status cannot change here (PENDING entries are decided with approve
// and reject, and are not editable).
func (s *Server) handleReplacePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var next event.AllowlistEntry
	if !decodeBody(w, r, &next, true, "invalid request body") {
		return
	}
	if next.ID != "" && next.ID != id {
		writeError(w, http.StatusBadRequest, "id in the body does not match the URL")
		return
	}
	cur, ok := s.editableEntry(w, r, id)
	if !ok {
		return
	}
	if next.Status != "" && next.Status != cur.Status {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("status cannot change from %s with PUT", cur.Status))
		return
	}
	next.ID, next.CreatedAt, next.CreatedBy, next.Status, next.Learned = cur.ID, cur.CreatedAt, cur.CreatedBy, cur.Status, cur.Learned
	s.saveEntry(w, r, &next)
}

// handlePatchPolicy changes some of an entry's editable fields (PATCH),
// such as {"enabled": false}. A field set to null is cleared. Any field
// outside editableFields is refused.
func (s *Server) handlePatchPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var patch map[string]json.RawMessage
	if !decodeBody(w, r, &patch, false, `invalid request body: want a JSON object such as {"enabled": false}`) {
		return
	}
	if len(patch) == 0 {
		writeError(w, http.StatusBadRequest, `empty patch: give the fields to change, such as {"enabled": false}`)
		return
	}
	keys := make([]string, 0, len(patch))
	for k := range patch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !editableFields[k] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("%q cannot be changed with PATCH", k))
			return
		}
	}
	cur, ok := s.editableEntry(w, r, id)
	if !ok {
		return
	}
	next, err := applyPatch(cur, patch)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid patch: "+err.Error())
		return
	}
	s.saveEntry(w, r, next)
}

// applyPatch returns a copy of cur with the patch's fields decoded over it.
func applyPatch(cur *event.AllowlistEntry, patch map[string]json.RawMessage) (*event.AllowlistEntry, error) {
	base, err := json.Marshal(cur)
	if err != nil {
		return nil, err
	}
	var next event.AllowlistEntry
	if err := json.Unmarshal(base, &next); err != nil {
		return nil, err
	}
	p, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		return nil, err
	}
	return &next, nil
}

// saveEntry validates an edited entry, stores it and reloads the policy.
func (s *Server) saveEntry(w http.ResponseWriter, r *http.Request, e *event.AllowlistEntry) {
	if err := validateEntry(e); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch err := s.store.UpdateAllowlistEntry(r.Context(), e); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return
	case errors.Is(err, store.ErrPending):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.logger.Error("update allowlist entry failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	if !s.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, e)
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
	if !decodeBody(w, r, &req, true, `invalid request body: want {"scope": "fleet"} or {"scope": "host", "host_id": "..."}`) {
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
