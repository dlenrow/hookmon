package server

import (
	"strings"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/pkg/version"
	"github.com/dlenrow/hookmon/server/api"
	"github.com/dlenrow/hookmon/server/connectors"
)

// settings is what GET /api/v1/settings reports, for the dashboard's
// Settings page: the bound addresses, enrollment by token name, and the
// connectors' counts. It holds no secrets. It is called only after Ready,
// once the addresses are set.
func (s *Server) settings() api.Settings {
	now := time.Now()
	st := api.Settings{
		Version:    version.Version,
		TLS:        s.cfg.UseTLS(),
		GRPCAddr:   s.grpcAddr,
		EnrollAddr: s.enrollAddr,
		HTTPAddr:   s.httpAddr,
	}
	st.Enrollment.Enabled = s.enrollAddr != ""
	for _, t := range s.cfg.Enrollment.Tokens {
		st.Enrollment.Tokens = append(st.Enrollment.Tokens, api.EnrollmentTokenStatus{
			Name: t.Name, Expires: t.Expires, Expired: !t.Expires.After(now), SingleUse: t.SingleUse,
		})
	}
	minSev := connectorMinSeverity(s.cfg.Connectors)
	for _, c := range s.dispatcher.Stats() {
		st.Connectors = append(st.Connectors, api.ConnectorStatus{
			Name: c.Connector, MinSeverity: minSev[c.Connector],
			Sent: c.Sent, Dropped: c.Dropped, Failed: c.Failed, Queued: c.Queued,
		})
	}
	return st
}

// connectorMinSeverity maps each configured connector's name to its
// min_severity, ALERT when unset.
func connectorMinSeverity(c connectors.Config) map[string]string {
	m := map[string]string{}
	add := func(name string, d connectors.Delivery) {
		sev := strings.ToUpper(string(d.MinSeverity))
		if sev == "" {
			sev = string(event.SeverityAlert)
		}
		m[name] = sev
	}
	if c.Syslog != nil {
		add("syslog", c.Syslog.Delivery)
	}
	if c.Splunk != nil {
		add("splunk", c.Splunk.Delivery)
	}
	if c.Elastic != nil {
		add("elasticsearch", c.Elastic.Delivery)
	}
	if c.Webhook != nil {
		add("webhook", c.Webhook.Delivery)
	}
	if c.Kafka != nil {
		add("kafka", c.Kafka.Delivery)
	}
	return m
}
