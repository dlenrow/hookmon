package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/store"
)

// learningView is a learning window as the API shows it.
type learningView struct {
	Scope     string    `json:"scope"` // "fleet" or "host"
	HostID    string    `json:"host_id,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	StartedBy string    `json:"started_by,omitempty"`
	Active    bool      `json:"active"`
}

func viewLearning(w event.LearningWindow, now time.Time) learningView {
	v := learningView{
		Scope: "fleet", HostID: w.HostID,
		StartedAt: w.StartedAt, EndsAt: w.EndsAt, StartedBy: w.StartedBy,
		Active: w.ActiveAt(now),
	}
	if w.HostID != "" {
		v.Scope = "host"
	}
	return v
}

// learningRequest is the body of a PUT that starts learning mode: an end
// time, or a duration from now ("90m", "36h", "7d").
type learningRequest struct {
	EndsAt   *time.Time `json:"ends_at"`
	Duration string     `json:"duration"`
}

// handleGetLearning lists the learning windows, ended ones included, with
// whether each is active now.
func (s *Server) handleGetLearning(w http.ResponseWriter, r *http.Request) {
	windows, err := s.store.GetLearningWindows(r.Context())
	if err != nil {
		s.logger.Error("query learning windows failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	now := time.Now()
	views := make([]learningView, 0, len(windows))
	for _, lw := range windows {
		views = append(views, viewLearning(lw, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"now": now.UTC(), "windows": views})
}

func (s *Server) handleStartFleetLearning(w http.ResponseWriter, r *http.Request) {
	s.startLearning(w, r, "")
}

func (s *Server) handleStartHostLearning(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostID")
	if _, err := s.store.GetHost(r.Context(), hostID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("host %s is not enrolled", hostID))
			return
		}
		s.logger.Error("look up host failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.startLearning(w, r, hostID)
}

// startLearning starts (or restarts, with a new end time) learning mode for
// the fleet (hostID empty) or one host.
func (s *Server) startLearning(w http.ResponseWriter, r *http.Request, hostID string) {
	var req learningRequest
	if !decodeBody(w, r, &req, true, `invalid request body: want {"duration": "7d"} or {"ends_at": "<RFC 3339 time>"}`) {
		return
	}
	now := time.Now().UTC()
	var end time.Time
	switch {
	case req.EndsAt != nil && req.Duration != "":
		writeError(w, http.StatusBadRequest, "give ends_at or duration, not both")
		return
	case req.EndsAt != nil:
		end = req.EndsAt.UTC()
	case req.Duration != "":
		d, err := ParseLearningDuration(req.Duration)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		end = now.Add(d)
	default:
		writeError(w, http.StatusBadRequest, "learning mode needs an end: give ends_at or duration")
		return
	}
	if !end.After(now) {
		writeError(w, http.StatusBadRequest, "ends_at must be in the future")
		return
	}
	lw := event.LearningWindow{HostID: hostID, StartedAt: now, EndsAt: end, StartedBy: "api"}
	if err := s.store.SetLearningWindow(r.Context(), lw); err != nil {
		s.logger.Error("set learning window failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !s.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, viewLearning(lw, now))
}

func (s *Server) handleStopFleetLearning(w http.ResponseWriter, r *http.Request) {
	s.stopLearning(w, r, "")
}

func (s *Server) handleStopHostLearning(w http.ResponseWriter, r *http.Request) {
	s.stopLearning(w, r, chi.URLParam(r, "hostID"))
}

// stopLearning ends learning mode for the fleet (hostID empty) or one host
// now. PENDING entries stay for review.
func (s *Server) stopLearning(w http.ResponseWriter, r *http.Request, hostID string) {
	if err := s.store.DeleteLearningWindow(r.Context(), hostID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no learning window for that scope")
			return
		}
		s.logger.Error("delete learning window failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !s.reload(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ParseLearningDuration parses a Go duration ("90m", "36h") or a whole
// number of days ("7d"). It must be positive.
func ParseLearningDuration(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("duration %q: want a Go duration (90m, 36h) or whole days (7d)", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("duration %q: want a Go duration (90m, 36h) or whole days (7d)", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}
