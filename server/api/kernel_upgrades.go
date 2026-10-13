package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

func (s *Server) handleKernelUpgrades(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	upgrades, err := s.store.KernelUpgrades(ctx)
	if err != nil {
		s.logger.Error("kernel upgrades query failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(upgrades)
}
