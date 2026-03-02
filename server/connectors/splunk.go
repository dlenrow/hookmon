package connectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// SplunkConnector sends events to a Splunk HTTP Event Collector (HEC) endpoint.
type SplunkConnector struct {
	httpClient *http.Client
	hecURL     string
	token      string
	index      string
	sourceType string
	logger     *zap.Logger
}

// splunkEnvelope wraps an event in the Splunk HEC JSON envelope.
type splunkEnvelope struct {
	Time       float64          `json:"time"`
	SourceType string           `json:"sourcetype"`
	Index      string           `json:"index,omitempty"`
	Event      *event.HookEvent `json:"event"`
}

// NewSplunkConnector creates a connector that POSTs events to Splunk HEC.
// The url should include the full HEC endpoint path (e.g.,
// "https://splunk.example.com:8088/services/collector/event").
func NewSplunkConnector(url, token, index string, logger *zap.Logger) *SplunkConnector {
	return &SplunkConnector{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		hecURL:     url,
		token:      token,
		index:      index,
		sourceType: "hookmon:event",
		logger:     logger,
	}
}

// Name returns the connector identifier.
func (s *SplunkConnector) Name() string { return "splunk" }

// Send marshals the event into a Splunk HEC envelope and POSTs it.
func (s *SplunkConnector) Send(evt *event.HookEvent) error {
	envelope := splunkEnvelope{
		Time:       float64(evt.Timestamp.UnixNano()) / 1e9,
		SourceType: s.sourceType,
		Index:      s.index,
		Event:      evt,
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("splunk marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.hecURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("splunk create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("splunk HEC request failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("splunk request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s.logger.Error("splunk HEC non-2xx response",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)),
			zap.String("event_id", evt.ID),
		)
		return fmt.Errorf("splunk HEC status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Close is a no-op for the Splunk connector; the HTTP client has no persistent
// resources to release.
func (s *SplunkConnector) Close() error {
	return nil
}
