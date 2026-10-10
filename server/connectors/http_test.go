package connectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dlenrow/hookmon/pkg/event"
)

// siemRequest is one request an httptest sink received.
type siemRequest struct {
	Method, Path string
	Header       http.Header
	Body         []byte
	At           time.Time
}

// siemSink is an httptest server that records requests and answers with
// the status codes in replies, in order (200 once they run out).
type siemSink struct {
	*httptest.Server
	mu      sync.Mutex
	reqs    []siemRequest
	replies []int
	body    func(r siemRequest) string
}

func siemNewSink(t *testing.T, replies ...int) *siemSink {
	t.Helper()
	s := &siemSink{replies: replies}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		req := siemRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: data, At: time.Now()}
		s.mu.Lock()
		s.reqs = append(s.reqs, req)
		code := http.StatusOK
		if len(s.replies) > 0 {
			code, s.replies = s.replies[0], s.replies[1:]
		}
		body := s.body
		s.mu.Unlock()
		w.WriteHeader(code)
		if body != nil {
			io.WriteString(w, body(req))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// setBody sets what the sink answers with.
func (s *siemSink) setBody(f func(siemRequest) string) {
	s.mu.Lock()
	s.body = f
	s.mu.Unlock()
}

func (s *siemSink) requests() []siemRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]siemRequest(nil), s.reqs...)
}

func siemBatch(n int) []*event.HookEvent {
	out := make([]*event.HookEvent, n)
	for i := range out {
		e := siemCanary("evt-" + string(rune('a'+i)))
		e.Timestamp = time.Date(2026, 10, 9+i%2, 23, 59, 0, 0, time.UTC)
		out[i] = e
	}
	return out
}

// --- Splunk HEC ---

func TestSplunk_BatchAuthAndEnvelope(t *testing.T) {
	sink := siemNewSink(t)
	c, err := NewSplunkConnector(SplunkConfig{URL: sink.URL + "/services/collector/event", Token: "hec-secret", Index: "sec"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), siemBatch(3)); err != nil {
		t.Fatal(err)
	}
	reqs := sink.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests for one batch of 3, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodPost || r.Path != "/services/collector/event" {
		t.Errorf("%s %s", r.Method, r.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Splunk hec-secret" {
		t.Errorf("Authorization = %q", got)
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	var n int
	for dec.More() {
		var env struct {
			Time       float64          `json:"time"`
			Host       string           `json:"host"`
			Source     string           `json:"source"`
			SourceType string           `json:"sourcetype"`
			Index      string           `json:"index"`
			Event      *event.HookEvent `json:"event"`
		}
		if err := dec.Decode(&env); err != nil {
			t.Fatal(err)
		}
		n++
		if env.SourceType != "hookmon:event" || env.Index != "sec" || env.Host != "web-01" || env.Source != "hookmon" {
			t.Errorf("envelope %+v", env)
		}
		if env.Event == nil || env.Event.BPFDetail == nil || env.Event.BPFDetail.ProgName != "hello_count" {
			t.Errorf("event %+v", env.Event)
		}
		if want := float64(env.Event.Timestamp.UnixMilli()) / 1e3; env.Time != want {
			t.Errorf("time %v, want %v", env.Time, want)
		}
	}
	if n != 3 {
		t.Errorf("%d envelopes, want 3", n)
	}
}

func TestSplunk_StatusClassification(t *testing.T) {
	for code, retry := range map[int]bool{400: false, 401: false, 403: false, 429: true, 500: true, 503: true} {
		sink := siemNewSink(t, code)
		c, _ := NewSplunkConnector(SplunkConfig{URL: sink.URL, Token: "x"}, zap.NewNop())
		err := c.Send(context.Background(), siemBatch(1))
		if err == nil || isRetryable(err) != retry {
			t.Errorf("status %d: err %v, retryable %v, want %v", code, err, isRetryable(err), retry)
		}
	}
}

// --- Elasticsearch ---

// siemBulkLines splits an NDJSON _bulk body into action and document pairs.
func siemBulkLines(t *testing.T, body []byte) (actions []bulkAction, docs []*event.HookEvent) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for i := 0; sc.Scan(); i++ {
		if i%2 == 0 {
			var a bulkAction
			if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
				t.Fatalf("action line %q: %v", sc.Text(), err)
			}
			actions = append(actions, a)
		} else {
			var d event.HookEvent
			if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
				t.Fatalf("doc line: %v", err)
			}
			docs = append(docs, &d)
		}
	}
	if !bytes.HasSuffix(body, []byte("\n")) {
		t.Error("bulk body does not end in a newline")
	}
	return actions, docs
}

// TestElastic_BulkBatchDailyIndexAuth: one _bulk call per batch (the old
// connector made one call per event), each document in the daily index for
// its UTC date with the event ID as _id, and the credentials sent.
func TestElastic_BulkBatchDailyIndexAuth(t *testing.T) {
	sink := siemNewSink(t)
	sink.setBody(func(siemRequest) string { return `{"errors":false,"items":[]}` })
	off := false
	for _, tc := range []struct {
		name string
		cfg  ElasticConfig
		auth string
	}{
		{"basic", ElasticConfig{URL: sink.URL + "/", Username: "hookmon", Password: "pw", ILM: ElasticILMConfig{Setup: &off}},
			"Basic " + base64.StdEncoding.EncodeToString([]byte("hookmon:pw"))},
		{"api key", ElasticConfig{URL: sink.URL, APIKey: "aWQ6a2V5", IndexPrefix: "sec-hookmon", ILM: ElasticILMConfig{Setup: &off}}, "ApiKey aWQ6a2V5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sink.requests())
			c, err := NewElasticConnector(tc.cfg, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Setup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Send(context.Background(), siemBatch(3)); err != nil {
				t.Fatal(err)
			}
			reqs := sink.requests()[before:]
			if len(reqs) != 1 {
				t.Fatalf("%d requests (ILM setup off, one batch), want 1", len(reqs))
			}
			r := reqs[0]
			if r.Path != "/_bulk" || r.Header.Get("Content-Type") != "application/x-ndjson" {
				t.Errorf("%s %s %s", r.Method, r.Path, r.Header.Get("Content-Type"))
			}
			if got := r.Header.Get("Authorization"); got != tc.auth {
				t.Errorf("Authorization = %q, want %q", got, tc.auth)
			}
			prefix := tc.cfg.IndexPrefix
			if prefix == "" {
				prefix = "hookmon-events"
			}
			actions, docs := siemBulkLines(t, r.Body)
			if len(actions) != 3 || len(docs) != 3 {
				t.Fatalf("%d actions and %d docs, want 3 each", len(actions), len(docs))
			}
			want := []string{prefix + "-2026.10.09", prefix + "-2026.10.10", prefix + "-2026.10.09"}
			for i, a := range actions {
				if a.Index == nil || a.Index.Index != want[i] || a.Index.ID != docs[i].ID {
					t.Errorf("action %d: %+v, want index %s and _id %s", i, a.Index, want[i], docs[i].ID)
				}
			}
		})
	}
}

// TestElastic_ILMSetup: Setup installs the delete-after policy and an index
// template that applies it to the daily indices.
func TestElastic_ILMSetup(t *testing.T) {
	sink := siemNewSink(t)
	c, err := NewElasticConnector(ElasticConfig{URL: sink.URL, IndexPrefix: "hm", APIKey: "k", ILM: ElasticILMConfig{DeleteAfter: "30d"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqs := sink.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d setup requests, want 2", len(reqs))
	}
	if reqs[0].Method != http.MethodPut || reqs[0].Path != "/_ilm/policy/hookmon-events" {
		t.Errorf("policy request %s %s", reqs[0].Method, reqs[0].Path)
	}
	var policy struct {
		Policy struct {
			Phases map[string]struct {
				MinAge  string                     `json:"min_age"`
				Actions map[string]json.RawMessage `json:"actions"`
			} `json:"phases"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(reqs[0].Body, &policy); err != nil {
		t.Fatal(err)
	}
	del, ok := policy.Policy.Phases["delete"]
	if _, hasDelete := del.Actions["delete"]; !ok || del.MinAge != "30d" || !hasDelete {
		t.Errorf("policy %s", reqs[0].Body)
	}
	if reqs[1].Method != http.MethodPut || reqs[1].Path != "/_index_template/hookmon-events" {
		t.Errorf("template request %s %s", reqs[1].Method, reqs[1].Path)
	}
	var tmpl struct {
		IndexPatterns []string `json:"index_patterns"`
		Template      struct {
			Settings map[string]string `json:"settings"`
			Mappings struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
			} `json:"mappings"`
		} `json:"template"`
	}
	if err := json.Unmarshal(reqs[1].Body, &tmpl); err != nil {
		t.Fatal(err)
	}
	if len(tmpl.IndexPatterns) != 1 || tmpl.IndexPatterns[0] != "hm-*" ||
		tmpl.Template.Settings["index.lifecycle.name"] != "hookmon-events" ||
		tmpl.Template.Mappings.Properties["timestamp"].Type != "date" {
		t.Errorf("template %s", reqs[1].Body)
	}
	for _, r := range reqs {
		if r.Header.Get("Authorization") != "ApiKey k" {
			t.Errorf("%s without credentials", r.Path)
		}
	}

	// A cluster that refuses the setup fails it.
	bad := siemNewSink(t, http.StatusForbidden)
	c2, _ := NewElasticConnector(ElasticConfig{URL: bad.URL}, zap.NewNop())
	if err := c2.Setup(context.Background()); err == nil {
		t.Error("Setup succeeded against a 403")
	}
}

// TestElastic_BulkItemErrors: a 200 whose items failed is an error,
// retryable only when an item failed with 429 or 5xx.
func TestElastic_BulkItemErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		retry  bool
	}{{400, false}, {429, true}, {503, true}} {
		sink := siemNewSink(t)
		status := tc.status
		sink.setBody(func(siemRequest) string {
			return `{"errors":true,"items":[{"index":{"_id":"a","status":201}},{"index":{"_id":"b","status":` +
				strconv.Itoa(status) + `,"error":{"type":"x"}}}]}`
		})
		c, _ := NewElasticConnector(ElasticConfig{URL: sink.URL}, zap.NewNop())
		err := c.Send(context.Background(), siemBatch(2))
		if err == nil || isRetryable(err) != tc.retry || !strings.Contains(err.Error(), "1 of 2") {
			t.Errorf("item status %d: %v (retryable %v)", tc.status, err, isRetryable(err))
		}
	}
}

// --- Webhook ---

// TestWebhook_SingleAndBatched: without batching each POST is one JSON
// object; with batch_size above 1 each POST is a JSON array. Custom
// headers go on every request.
func TestWebhook_SingleAndBatched(t *testing.T) {
	sink := siemNewSink(t)
	hdr := map[string]string{"Authorization": "Bearer tok", "X-Team": "soc"}

	one, err := NewWebhookConnector(WebhookConfig{URL: sink.URL, Headers: hdr}, false, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Send(context.Background(), siemBatch(1)); err != nil {
		t.Fatal(err)
	}
	var obj event.HookEvent
	if err := json.Unmarshal(sink.requests()[0].Body, &obj); err != nil || obj.ID != "evt-a" {
		t.Errorf("single body %s: %v", sink.requests()[0].Body, err)
	}

	many, _ := NewWebhookConnector(WebhookConfig{URL: sink.URL, Headers: hdr}, true, zap.NewNop())
	if err := many.Send(context.Background(), siemBatch(3)); err != nil {
		t.Fatal(err)
	}
	reqs := sink.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2", len(reqs))
	}
	var arr []event.HookEvent
	if err := json.Unmarshal(reqs[1].Body, &arr); err != nil || len(arr) != 3 {
		t.Errorf("batched body %s: %v", reqs[1].Body, err)
	}
	for _, r := range reqs {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Team") != "soc" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers %v", r.Header)
		}
	}
}

// siemQueue runs one connector behind a real queue and worker, with a fast
// retry policy, as the dispatcher would.
func siemQueue(t *testing.T, c Connector, del Delivery, retry retryPolicy) *Dispatcher {
	t.Helper()
	d := newDispatcher(nil, zaptest.NewLogger(t, zaptest.Level(zap.ErrorLevel)))
	d.add(c, del.withDefaults(1), retry)
	d.start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.Close(ctx)
	})
	return d
}

func siemWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWebhook_NoRetryOn4xx: a 4xx other than 429 is sent once. The old
// connector's comment said so, but its loop retried every error.
func TestWebhook_NoRetryOn4xx(t *testing.T) {
	sink := siemNewSink(t, 400, 400, 400)
	c, _ := NewWebhookConnector(WebhookConfig{URL: sink.URL}, false, zap.NewNop())
	d := siemQueue(t, c, Delivery{MinSeverity: event.SeverityInfo}, retryPolicy{attempts: 3, base: 10 * time.Millisecond})
	d.Send(siemCanary("bad"))
	siemWait(t, "the failure to be counted", func() bool { return d.Stats()[0].Failed == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(sink.requests()); n != 1 {
		t.Errorf("%d requests for a 400, want 1 (no retry)", n)
	}
}

// TestWebhook_RetryWithBackoffOn5xx: 503, 502, then 200 delivers on the
// third try, waiting base then 2*base between tries.
func TestWebhook_RetryWithBackoffOn5xx(t *testing.T) {
	sink := siemNewSink(t, 503, 502)
	c, _ := NewWebhookConnector(WebhookConfig{URL: sink.URL}, false, zap.NewNop())
	base := 40 * time.Millisecond
	d := siemQueue(t, c, Delivery{MinSeverity: event.SeverityInfo}, retryPolicy{attempts: 3, base: base})
	d.Send(siemCanary("flaky"))
	siemWait(t, "delivery", func() bool { return d.Stats()[0].Sent == 1 })
	reqs := sink.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3", len(reqs))
	}
	if gap := reqs[1].At.Sub(reqs[0].At); gap < base {
		t.Errorf("first retry after %v, want at least %v", gap, base)
	}
	if gap := reqs[2].At.Sub(reqs[1].At); gap < 2*base {
		t.Errorf("second retry after %v, want at least %v", gap, 2*base)
	}
	if st := d.Stats()[0]; st.Failed != 0 || st.Dropped != 0 {
		t.Errorf("stats %+v", st)
	}

	// Still failing after every attempt: counted as failed.
	sink2 := siemNewSink(t, 500, 500, 500)
	c2, _ := NewWebhookConnector(WebhookConfig{URL: sink2.URL}, false, zap.NewNop())
	d2 := siemQueue(t, c2, Delivery{MinSeverity: event.SeverityInfo}, retryPolicy{attempts: 3, base: time.Millisecond})
	d2.Send(siemCanary("down"))
	siemWait(t, "failure", func() bool { return d2.Stats()[0].Failed == 1 })
	if n := len(sink2.requests()); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}
}

// TestWebhook_BatchingByQueue: with batch_size 3 and a long flush
// interval, five events go out as one array of 3 and, at Close, one of 2.
func TestWebhook_BatchingByQueue(t *testing.T) {
	sink := siemNewSink(t)
	c, _ := NewWebhookConnector(WebhookConfig{URL: sink.URL}, true, zap.NewNop())
	d := newDispatcher(nil, zap.NewNop())
	d.add(c, Delivery{MinSeverity: event.SeverityInfo, BatchSize: 3, FlushInterval: time.Hour}.withDefaults(1), defaultRetry)
	d.start()
	for _, e := range siemBatch(5) {
		d.Send(e)
	}
	siemWait(t, "the first batch", func() bool { return len(sink.requests()) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	reqs := sink.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2", len(reqs))
	}
	for i, want := range []int{3, 2} {
		var arr []event.HookEvent
		if err := json.Unmarshal(reqs[i].Body, &arr); err != nil || len(arr) != want {
			t.Errorf("request %d: %d events (%v), want %d", i, len(arr), err, want)
		}
	}

	// A partial batch goes out after the flush interval.
	sink2 := siemNewSink(t)
	c2, _ := NewWebhookConnector(WebhookConfig{URL: sink2.URL}, true, zap.NewNop())
	d2 := siemQueue(t, c2, Delivery{MinSeverity: event.SeverityInfo, BatchSize: 10, FlushInterval: 50 * time.Millisecond}, defaultRetry)
	start := time.Now()
	d2.Send(siemCanary("lonely"))
	siemWait(t, "the flush", func() bool { return len(sink2.requests()) == 1 })
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Errorf("flushed after %v, before the interval", el)
	}
}
