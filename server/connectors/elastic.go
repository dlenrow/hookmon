package connectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// ElasticConnector sends events to Elasticsearch using the _bulk API.
type ElasticConnector struct {
	httpClient   *http.Client
	baseURL      string
	indexPattern string // e.g. "hookmon-events" — date suffix appended automatically
	logger       *zap.Logger
}

// NewElasticConnector creates a connector that indexes events into
// Elasticsearch. The indexPattern is used as a prefix; the current date is
// appended as "-YYYY.MM.DD" to produce daily indices (e.g.
// "hookmon-events-2026.03.01").
func NewElasticConnector(url, indexPattern string, logger *zap.Logger) *ElasticConnector {
	// Normalise the base URL to avoid double slashes.
	url = strings.TrimRight(url, "/")

	return &ElasticConnector{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		baseURL:      url,
		indexPattern: indexPattern,
		logger:       logger,
	}
}

// Name returns the connector identifier.
func (e *ElasticConnector) Name() string { return "elasticsearch" }

// Send indexes a single event using the Elasticsearch _bulk API with a
// newline-delimited JSON (NDJSON) payload.
func (e *ElasticConnector) Send(evt *event.HookEvent) error {
	index := e.indexName(evt.Timestamp)

	// Action line: tells Elasticsearch to index the document.
	action := bulkAction{
		Index: &bulkIndex{
			Index: index,
			ID:    evt.ID,
		},
	}
	actionLine, err := json.Marshal(action)
	if err != nil {
		return fmt.Errorf("elastic marshal action: %w", err)
	}

	docLine, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("elastic marshal event: %w", err)
	}

	// The _bulk API requires NDJSON: each line terminated by \n, with a
	// trailing newline after the last line.
	var buf bytes.Buffer
	buf.Write(actionLine)
	buf.WriteByte('\n')
	buf.Write(docLine)
	buf.WriteByte('\n')

	endpoint := fmt.Sprintf("%s/_bulk", e.baseURL)
	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("elastic create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		e.logger.Error("elasticsearch request failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("elastic request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		e.logger.Error("elasticsearch non-2xx response",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)),
			zap.String("event_id", evt.ID),
		)
		return fmt.Errorf("elastic status %d: %s", resp.StatusCode, string(respBody))
	}

	// Check the response body for per-item errors.
	var bulkResp bulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		e.logger.Warn("elasticsearch response decode failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		// The HTTP status was 2xx so the index likely succeeded.
		return nil
	}

	if bulkResp.Errors {
		e.logger.Warn("elasticsearch bulk response reported errors",
			zap.String("event_id", evt.ID),
		)
		return fmt.Errorf("elastic bulk response contained errors for event %s", evt.ID)
	}

	return nil
}

// Close is a no-op for the Elasticsearch connector.
func (e *ElasticConnector) Close() error {
	return nil
}

// indexName produces the daily index name from the pattern and event timestamp.
func (e *ElasticConnector) indexName(ts time.Time) string {
	return fmt.Sprintf("%s-%s", e.indexPattern, ts.UTC().Format("2006.01.02"))
}

// bulkAction represents the action metadata line in a _bulk request.
type bulkAction struct {
	Index *bulkIndex `json:"index"`
}

// bulkIndex is the index action metadata.
type bulkIndex struct {
	Index string `json:"_index"`
	ID    string `json:"_id,omitempty"`
}

// bulkResponse is a minimal representation of the Elasticsearch _bulk API response.
type bulkResponse struct {
	Errors bool `json:"errors"`
}
