package observability

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dlenrow/hookmon/agent/registry"
)

// StatusResponse is the JSON payload returned by the /status endpoint.
type StatusResponse struct {
	Host     string                    `json:"host"`
	PolledAt time.Time                 `json:"polled_at"`
	Overall  string                    `json:"overall"`
	Sensors  []registry.SensorStatus   `json:"sensors"`
	Version  string                    `json:"version"`
}

// SensorSnapshot is a simplified sensor status for external consumption (e.g. by the collector).
type SensorSnapshot struct {
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	LastBeat time.Time `json:"last_beat"`
}

// StatusHandler returns an http.HandlerFunc that serves the sensor bus /status endpoint.
func StatusHandler(reg *registry.Registry, hostname, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := StatusResponse{
			Host:     hostname,
			PolledAt: time.Now().UTC(),
			Overall:  reg.Overall(),
			Sensors:  reg.Snapshot(),
			Version:  version,
		}
		json.NewEncoder(w).Encode(resp)
	}
}
