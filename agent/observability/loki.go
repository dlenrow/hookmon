package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// LokiPusher batches HookEvents and pushes them to Loki's HTTP API.
type LokiPusher struct {
	url    string
	client *http.Client
	logger *zap.Logger

	mu    sync.Mutex
	batch []lokiEntry
	timer *time.Timer

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type lokiEntry struct {
	labels map[string]string
	ts     time.Time
	line   string
}

// Loki push API JSON structures.
type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

const (
	lokiFlushInterval = 1 * time.Second
	lokiMaxBatch      = 10
)

// NewLokiPusher creates a Loki pusher targeting the given base URL (e.g. http://localhost:3100).
func NewLokiPusher(baseURL string, logger *zap.Logger) *LokiPusher {
	ctx, cancel := context.WithCancel(context.Background())
	lp := &LokiPusher{
		url:    baseURL + "/loki/api/v1/push",
		client: &http.Client{Timeout: 5 * time.Second},
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go lp.flushLoop()
	return lp
}

// Push adds a HookEvent to the batch.
func (lp *LokiPusher) Push(evt *event.HookEvent) {
	line, err := json.Marshal(evt)
	if err != nil {
		lp.logger.Error("loki: marshal event", zap.Error(err))
		return
	}

	sensor := sensorFromEventType(evt.EventType)
	entry := lokiEntry{
		labels: map[string]string{
			"service":    "hookmon",
			"event_type": string(evt.EventType),
			"severity":   string(evt.Severity),
			"hostname":   evt.Hostname,
			"sensor":     sensor,
		},
		ts:   evt.Timestamp,
		line: string(line),
	}

	lp.mu.Lock()
	lp.batch = append(lp.batch, entry)
	shouldFlush := len(lp.batch) >= lokiMaxBatch
	lp.mu.Unlock()

	if shouldFlush {
		lp.flush()
	}
}

// Close flushes remaining entries and shuts down.
func (lp *LokiPusher) Close() {
	lp.cancel()
	<-lp.done
	lp.flush()
}

func (lp *LokiPusher) flushLoop() {
	defer close(lp.done)
	ticker := time.NewTicker(lokiFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lp.ctx.Done():
			return
		case <-ticker.C:
			lp.flush()
		}
	}
}

func (lp *LokiPusher) flush() {
	lp.mu.Lock()
	entries := lp.batch
	lp.batch = nil
	lp.mu.Unlock()

	if len(entries) == 0 {
		return
	}

	// Group entries by label set.
	streams := make(map[string]*lokiStream)
	for _, e := range entries {
		key := fmt.Sprintf("%v", e.labels)
		s, ok := streams[key]
		if !ok {
			s = &lokiStream{Stream: e.labels}
			streams[key] = s
		}
		tsNano := strconv.FormatInt(e.ts.UnixNano(), 10)
		s.Values = append(s.Values, []string{tsNano, e.line})
	}

	req := lokiPushRequest{}
	for _, s := range streams {
		req.Streams = append(req.Streams, *s)
	}

	body, err := json.Marshal(req)
	if err != nil {
		lp.logger.Error("loki: marshal push request", zap.Error(err))
		return
	}

	resp, err := lp.client.Post(lp.url, "application/json", bytes.NewReader(body))
	if err != nil {
		lp.logger.Warn("loki: push failed", zap.Error(err), zap.Int("entries", len(entries)))
		return
	}
	resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		lp.logger.Warn("loki: push returned non-2xx", zap.Int("status", resp.StatusCode), zap.Int("entries", len(entries)))
	}
}

func sensorFromEventType(et event.EventType) string {
	switch et {
	case event.EventBPFLoad, event.EventBPFAttach:
		return "bpf_syscall"
	case event.EventLDPreload:
		return "execve_preload"
	case event.EventSHMCreate:
		return "shm_monitor"
	case event.EventDlopen:
		return "dlopen_monitor"
	default:
		return "unknown"
	}
}
