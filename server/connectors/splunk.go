package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// SplunkConnector sends events to a Splunk HTTP Event Collector (HEC). A
// batch goes out as one POST holding one HEC envelope per event, which HEC
// accepts concatenated.
type SplunkConnector struct {
	client     *http.Client
	hecURL     string
	header     http.Header
	index      string
	sourceType string
	logger     *zap.Logger
}

// splunkEnvelope wraps an event in the Splunk HEC JSON envelope.
type splunkEnvelope struct {
	Time       float64          `json:"time"`
	Host       string           `json:"host,omitempty"`
	Source     string           `json:"source"`
	SourceType string           `json:"sourcetype"`
	Index      string           `json:"index,omitempty"`
	Event      *event.HookEvent `json:"event"`
}

// NewSplunkConnector creates a connector for the HEC endpoint in cfg.URL
// (for example https://splunk.example.com:8088/services/collector/event).
func NewSplunkConnector(cfg SplunkConfig, logger *zap.Logger) (*SplunkConnector, error) {
	client, err := newHTTPClient(cfg.CAFile, 15*time.Second)
	if err != nil {
		return nil, err
	}
	st := cfg.SourceType
	if st == "" {
		st = "hookmon:event"
	}
	return &SplunkConnector{
		client: client,
		hecURL: cfg.URL,
		header: http.Header{
			"Content-Type":  {"application/json"},
			"Authorization": {"Splunk " + cfg.Token},
		},
		index:      cfg.Index,
		sourceType: st,
		logger:     logger,
	}, nil
}

// Name returns the connector identifier.
func (s *SplunkConnector) Name() string { return "splunk" }

// Send POSTs the batch to HEC. The envelope's time is the event's
// detection time and its host the monitored host.
func (s *SplunkConnector) Send(ctx context.Context, batch []*event.HookEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, evt := range batch {
		ts := evt.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		env := splunkEnvelope{
			Time:       float64(ts.UnixMilli()) / 1e3,
			Host:       evt.Hostname,
			Source:     "hookmon",
			SourceType: s.sourceType,
			Index:      s.index,
			Event:      evt,
		}
		if err := enc.Encode(env); err != nil {
			return fmt.Errorf("splunk marshal event %s: %w", evt.ID, err)
		}
	}
	if _, err := doHTTP(ctx, s.client, http.MethodPost, s.hecURL, s.header, buf.Bytes()); err != nil {
		return fmt.Errorf("splunk HEC: %w", err)
	}
	return nil
}

// Close releases idle connections.
func (s *SplunkConnector) Close() error {
	s.client.CloseIdleConnections()
	return nil
}
