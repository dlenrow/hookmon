package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

const (
	defaultIndexPrefix = "hookmon-events"
	defaultILMPolicy   = "hookmon-events"
	defaultDeleteAfter = "90d"
)

// ElasticConnector sends events to Elasticsearch with the _bulk API: one
// request per batch, each event into the daily index for its UTC date
// (<prefix>-YYYY.MM.DD), with the event ID as the document ID so a retried
// batch overwrites rather than duplicates.
//
// At startup, Setup installs an ILM policy that deletes each daily index
// delete_after its creation, and an index template that applies the policy
// to <prefix>-* and maps timestamp as a date.
type ElasticConnector struct {
	client      *http.Client
	baseURL     string
	prefix      string
	header      http.Header
	setup       bool
	policy      string
	deleteAfter string
	logger      *zap.Logger
}

// NewElasticConnector creates the connector. It does not contact the
// cluster; Setup does.
func NewElasticConnector(cfg ElasticConfig, logger *zap.Logger) (*ElasticConnector, error) {
	client, err := newHTTPClient(cfg.CAFile, 30*time.Second)
	if err != nil {
		return nil, err
	}
	e := &ElasticConnector{
		client:      client,
		baseURL:     strings.TrimRight(cfg.URL, "/"),
		prefix:      cfg.IndexPrefix,
		header:      http.Header{},
		setup:       cfg.ILM.Setup == nil || *cfg.ILM.Setup,
		policy:      cfg.ILM.Policy,
		deleteAfter: cfg.ILM.DeleteAfter,
		logger:      logger,
	}
	if e.prefix == "" {
		e.prefix = defaultIndexPrefix
	}
	if e.policy == "" {
		e.policy = defaultILMPolicy
	}
	if e.deleteAfter == "" {
		e.deleteAfter = defaultDeleteAfter
	}
	switch {
	case cfg.APIKey != "":
		e.header.Set("Authorization", "ApiKey "+cfg.APIKey)
	case cfg.Username != "":
		e.header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password)))
	}
	return e, nil
}

// Name returns the connector identifier.
func (e *ElasticConnector) Name() string { return "elasticsearch" }

// Setup installs the ILM policy and the index template, unless ilm.setup
// is false. Both PUTs replace what is there, so it is safe at every start.
// It needs the manage_ilm and manage_index_templates cluster privileges.
func (e *ElasticConnector) Setup(ctx context.Context) error {
	if !e.setup {
		e.logger.Info("elasticsearch ILM setup skipped (ilm.setup is false)")
		return nil
	}
	policy := map[string]any{
		"policy": map[string]any{
			"_meta": map[string]any{"managed_by": "hookmon"},
			"phases": map[string]any{
				"delete": map[string]any{
					"min_age": e.deleteAfter,
					"actions": map[string]any{"delete": map[string]any{}},
				},
			},
		},
	}
	if err := e.put(ctx, "/_ilm/policy/"+url.PathEscape(e.policy), policy); err != nil {
		return fmt.Errorf("install ILM policy %s: %w", e.policy, err)
	}
	template := map[string]any{
		"index_patterns": []string{e.prefix + "-*"},
		"priority":       200,
		"_meta":          map[string]any{"managed_by": "hookmon"},
		"template": map[string]any{
			"settings": map[string]any{"index.lifecycle.name": e.policy},
			"mappings": map[string]any{
				"properties": map[string]any{
					"timestamp":  map[string]any{"type": "date"},
					"id":         map[string]any{"type": "keyword"},
					"host_id":    map[string]any{"type": "keyword"},
					"event_type": map[string]any{"type": "keyword"},
					"severity":   map[string]any{"type": "keyword"},
				},
			},
		},
	}
	if err := e.put(ctx, "/_index_template/"+url.PathEscape(e.policy), template); err != nil {
		return fmt.Errorf("install index template %s: %w", e.policy, err)
	}
	e.logger.Info("elasticsearch ILM policy and index template installed",
		zap.String("policy", e.policy),
		zap.String("index_pattern", e.prefix+"-*"),
		zap.String("delete_after", e.deleteAfter),
	)
	return nil
}

func (e *ElasticConnector) put(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	hdr := e.header.Clone()
	hdr.Set("Content-Type", "application/json")
	_, err = doHTTP(ctx, e.client, http.MethodPut, e.baseURL+path, hdr, data)
	return err
}

// Send indexes the batch with one _bulk request.
func (e *ElasticConnector) Send(ctx context.Context, batch []*event.HookEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, evt := range batch {
		if err := enc.Encode(bulkAction{Index: &bulkIndex{Index: e.indexName(evt.Timestamp), ID: evt.ID}}); err != nil {
			return fmt.Errorf("elastic marshal action: %w", err)
		}
		if err := enc.Encode(evt); err != nil {
			return fmt.Errorf("elastic marshal event %s: %w", evt.ID, err)
		}
	}
	hdr := e.header.Clone()
	hdr.Set("Content-Type", "application/x-ndjson")
	data, err := doHTTP(ctx, e.client, http.MethodPost, e.baseURL+"/_bulk", hdr, buf.Bytes())
	if err != nil {
		return fmt.Errorf("elastic bulk: %w", err)
	}

	// A 200 can still carry per-document failures.
	var resp bulkResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		e.logger.Warn("elasticsearch bulk response not understood; assuming success", zap.Error(err))
		return nil
	}
	if !resp.Errors {
		return nil
	}
	failed, transient := 0, false
	var first string
	for _, it := range resp.Items {
		r := it.Index
		if r == nil || r.Status < 300 {
			continue
		}
		failed++
		if r.Status == http.StatusTooManyRequests || r.Status >= 500 {
			transient = true
		}
		if first == "" {
			first = fmt.Sprintf("%s: status %d %s", r.ID, r.Status, snippet(r.Error))
		}
	}
	err = fmt.Errorf("elastic bulk: %d of %d documents failed (first %s)", failed, len(batch), first)
	if transient {
		return retryable(err)
	}
	return err
}

// Close releases idle connections.
func (e *ElasticConnector) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

// indexName is the daily index for an event time.
func (e *ElasticConnector) indexName(ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	return fmt.Sprintf("%s-%s", e.prefix, ts.UTC().Format("2006.01.02"))
}

// bulkAction is the action line of a _bulk request.
type bulkAction struct {
	Index *bulkIndex `json:"index"`
}

type bulkIndex struct {
	Index string `json:"_index"`
	ID    string `json:"_id,omitempty"`
}

// bulkResponse is the part of a _bulk response the connector reads.
type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []struct {
		Index *struct {
			ID     string          `json:"_id"`
			Status int             `json:"status"`
			Error  json.RawMessage `json:"error"`
		} `json:"index"`
	} `json:"items"`
}
