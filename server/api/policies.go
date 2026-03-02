package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/dlenrow/hookmon/pkg/event"
)

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.GetAllowlist(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var entry event.AllowlistEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	if err := s.store.CreateAllowlistEntry(r.Context(), &entry); err != nil {
		http.Error(w, `{"error":"failed to create policy"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteAllowlistEntry(r.Context(), id); err != nil {
		http.Error(w, `{"error":"failed to delete policy"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
