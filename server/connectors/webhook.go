package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// WebhookConnector POSTs events as JSON to any HTTP endpoint. Without
// batching each POST carries one event as a JSON object; with batching
// (batch_size above 1) each POST carries a JSON array of events.
//
// A network error, 429 or 5xx is retried by the connector's worker with
// exponential backoff; any other 4xx is not, since resending the same
// request cannot succeed.
type WebhookConnector struct {
	client *http.Client
	url    string
	header http.Header
	array  bool
	logger *zap.Logger
}

// NewWebhookConnector creates a webhook connector. array selects the
// batched body (a JSON array).
func NewWebhookConnector(cfg WebhookConfig, array bool, logger *zap.Logger) (*WebhookConnector, error) {
	client, err := newHTTPClient(cfg.CAFile, 10*time.Second)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{}
	for k, v := range cfg.Headers {
		hdr.Set(k, v)
	}
	hdr.Set("Content-Type", "application/json")
	return &WebhookConnector{client: client, url: cfg.URL, header: hdr, array: array, logger: logger}, nil
}

// Name returns the connector identifier.
func (w *WebhookConnector) Name() string { return "webhook" }

// Send POSTs the batch: one object when not batching (the batch then holds
// one event), otherwise an array.
func (w *WebhookConnector) Send(ctx context.Context, batch []*event.HookEvent) error {
	if !w.array {
		for _, evt := range batch {
			if err := w.post(ctx, evt); err != nil {
				return err
			}
		}
		return nil
	}
	return w.post(ctx, batch)
}

func (w *WebhookConnector) post(ctx context.Context, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}
	if _, err := doHTTP(ctx, w.client, http.MethodPost, w.url, w.header, body); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	return nil
}

// Close releases idle connections.
func (w *WebhookConnector) Close() error {
	w.client.CloseIdleConnections()
	return nil
}
