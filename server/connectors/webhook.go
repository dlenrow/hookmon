package connectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

const (
	// webhookMaxRetries is the number of delivery attempts (initial + retries).
	webhookMaxRetries = 3

	// webhookBaseDelay is the initial delay before the first retry.
	webhookBaseDelay = 500 * time.Millisecond
)

// WebhookConnector sends events as JSON POSTs to an arbitrary HTTP endpoint.
type WebhookConnector struct {
	httpClient *http.Client
	url        string
	headers    map[string]string
	logger     *zap.Logger
}

// NewWebhookConnector creates a connector that POSTs JSON events to the given
// URL. Custom headers (e.g. for authentication tokens) are included in every
// request.
func NewWebhookConnector(url string, headers map[string]string, logger *zap.Logger) *WebhookConnector {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}

	return &WebhookConnector{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		url:     url,
		headers: h,
		logger:  logger,
	}
}

// Name returns the connector identifier.
func (w *WebhookConnector) Name() string { return "webhook" }

// Send marshals the event to JSON and POSTs it to the configured URL. On
// transient failures (network errors or 5xx responses) the request is retried
// up to webhookMaxRetries times with exponential backoff.
func (w *WebhookConnector) Send(evt *event.HookEvent) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < webhookMaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt)
			w.logger.Debug("webhook retry",
				zap.Int("attempt", attempt+1),
				zap.Duration("delay", delay),
				zap.String("event_id", evt.ID),
			)
			time.Sleep(delay)
		}

		if err := w.doPost(body, evt.ID); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	w.logger.Error("webhook delivery failed after retries",
		zap.Int("attempts", webhookMaxRetries),
		zap.String("event_id", evt.ID),
		zap.Error(lastErr),
	)
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", webhookMaxRetries, lastErr)
}

// Close is a no-op for the webhook connector.
func (w *WebhookConnector) Close() error {
	return nil
}

// doPost performs a single POST request and returns an error if the delivery
// should be considered failed (and possibly retried).
func (w *WebhookConnector) doPost(body []byte, eventID string) error {
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 4xx errors (except 429) are not retryable — the request itself is bad.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return fmt.Errorf("webhook non-retryable status %d for event %s", resp.StatusCode, eventID)
	}

	// 5xx and 429 are considered transient.
	return fmt.Errorf("webhook transient status %d for event %s", resp.StatusCode, eventID)
}

// backoffDelay returns the delay for the given retry attempt using exponential
// backoff. attempt is 1-indexed (first retry = 1).
func backoffDelay(attempt int) time.Duration {
	return time.Duration(float64(webhookBaseDelay) * math.Pow(2, float64(attempt-1)))
}
