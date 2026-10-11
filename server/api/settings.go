package api

import (
	"net/http"
	"sort"
	"time"
)

// Settings is what GET /api/v1/settings reports: how a bus reaches and
// enrolls with this server, and how the connectors are doing. It never
// holds a secret: tokens appear by name only, and connector targets and
// credentials are left out.
type Settings struct {
	Version string `json:"version"`
	// TLS is false only in --insecure mode.
	TLS bool `json:"tls"`
	// GRPCAddr, EnrollAddr and HTTPAddr are the bound listener addresses.
	// EnrollAddr is empty when enrollment is off.
	GRPCAddr   string `json:"grpc_addr"`
	EnrollAddr string `json:"enroll_addr"`
	HTTPAddr   string `json:"http_addr"`

	Enrollment EnrollmentSettings `json:"enrollment"`
	Connectors []ConnectorStatus  `json:"connectors"`
	WebSocket  WebSocketSettings  `json:"websocket"`
}

// EnrollmentSettings describes enrollment without the token secrets.
type EnrollmentSettings struct {
	Enabled bool                    `json:"enabled"`
	Tokens  []EnrollmentTokenStatus `json:"tokens"`
}

// EnrollmentTokenStatus is one configured enrollment token, by name.
type EnrollmentTokenStatus struct {
	Name      string    `json:"name"`
	Expires   time.Time `json:"expires"`
	Expired   bool      `json:"expired"`
	SingleUse bool      `json:"single_use"`
}

// ConnectorStatus is one SIEM connector's delivery counts since the server
// started.
type ConnectorStatus struct {
	Name string `json:"name"`
	// MinSeverity is the lowest severity it receives: ALERT or CRITICAL
	// makes it an alert connector, INFO or WARN an event feed.
	MinSeverity string `json:"min_severity"`
	Sent        uint64 `json:"sent"`
	Dropped     uint64 `json:"dropped"`
	Failed      uint64 `json:"failed"`
	Queued      int    `json:"queued"`
}

// WebSocketSettings describes the live event feed.
type WebSocketSettings struct {
	HubStats
	// Protocol and TokenProtocolPrefix are the subprotocols a browser
	// offers (see WSTokenProtocolPrefix).
	Protocol            string `json:"protocol"`
	TokenProtocolPrefix string `json:"token_protocol_prefix"`
	// AllowedOrigins are the origins allowed besides the server's own.
	AllowedOrigins []string `json:"allowed_origins"`
}

// SettingsSource returns the server's current settings. The WebSocket part
// is filled in by the API.
type SettingsSource func() Settings

// SetSettingsSource sets what GET /api/v1/settings reports.
func (s *Server) SetSettingsSource(f SettingsSource) { s.settings = f }

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	var st Settings
	if s.settings != nil {
		st = s.settings()
	}
	if st.Connectors == nil {
		st.Connectors = []ConnectorStatus{}
	}
	if st.Enrollment.Tokens == nil {
		st.Enrollment.Tokens = []EnrollmentTokenStatus{}
	}
	st.WebSocket = WebSocketSettings{
		Protocol:            WSProtocol,
		TokenProtocolPrefix: WSTokenProtocolPrefix,
		AllowedOrigins:      []string{},
	}
	for o := range s.allowedOrigins {
		st.WebSocket.AllowedOrigins = append(st.WebSocket.AllowedOrigins, o)
	}
	sort.Strings(st.WebSocket.AllowedOrigins)
	if s.hub != nil {
		st.WebSocket.HubStats = s.hub.Stats()
	}
	writeJSON(w, http.StatusOK, st)
}
