package api

import (
	"net/http"
	"path"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Server holds dependencies for the HTTP API.
type Server struct {
	store    Store
	logger   *zap.Logger
	eventCh  <-chan *event.HookEvent
	reloader PolicyReloader
}

// NewServer creates a new API server.
func NewServer(store Store, logger *zap.Logger, eventCh <-chan *event.HookEvent) *Server {
	return &Server{
		store:   store,
		logger:  logger,
		eventCh: eventCh,
	}
}

// Router returns the configured HTTP router. With a non-nil dashboard, every
// path outside /api that no route matches is handed to it; unknown /api
// paths always get a JSON 404.
func (s *Server) Router(apiTokens []string, dashboard http.Handler) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Health check (no auth)
	r.Get("/api/v1/health", s.handleHealth)

	// Authenticated API routes
	auth := NewAuthMiddleware(apiTokens)
	r.Group(func(r chi.Router) {
		r.Use(auth.Handler)

		// Events
		r.Get("/api/v1/events", s.handleListEvents)
		r.Get("/api/v1/events/{id}", s.handleGetEvent)

		// Policies / Allowlist. Every write reloads the policy engine
		// before it answers.
		r.Get("/api/v1/policies", s.handleListPolicies)
		r.Post("/api/v1/policies", s.handleCreatePolicy)
		r.Delete("/api/v1/policies/{id}", s.handleDeletePolicy)
		r.Post("/api/v1/policies/{id}/approve", s.handleApprovePolicy)
		r.Post("/api/v1/policies/{id}/reject", s.handleRejectPolicy)

		// Learning mode
		r.Get("/api/v1/learning", s.handleGetLearning)
		r.Put("/api/v1/learning/fleet", s.handleStartFleetLearning)
		r.Delete("/api/v1/learning/fleet", s.handleStopFleetLearning)
		r.Put("/api/v1/learning/hosts/{hostID}", s.handleStartHostLearning)
		r.Delete("/api/v1/learning/hosts/{hostID}", s.handleStopHostLearning)

		// Hosts
		r.Get("/api/v1/hosts", s.handleListHosts)
		r.Get("/api/v1/hosts/{id}", s.handleGetHost)
	})

	// WebSocket (token in query param)
	r.Get("/api/v1/ws/events", s.handleWebSocket)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if dashboard == nil || isAPIPath(path.Clean("/"+r.URL.Path)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
			return
		}
		dashboard.ServeHTTP(w, r)
	})

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}
