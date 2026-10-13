package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// polRequest is one request the CLI made.
type polRequest struct{ method, path, body string }

// polServer records requests and answers each with the status the CLI
// expects for it.
func polServer(t *testing.T) (*CLI, *[]polRequest) {
	t.Helper()
	var got []polRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("%s %s: no bearer token", r.Method, r.URL)
		}
		got = append(got, polRequest{r.Method, r.URL.RequestURI(), string(body)})
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return &CLI{baseURL: srv.URL, token: "tok", client: srv.Client(), out: io.Discard}, &got
}

// TestCLI_PolicyAndLearningCommands: each command sends the request the
// API expects; malformed commands send nothing.
func TestCLI_PolicyAndLearningCommands(t *testing.T) {
	cases := []struct {
		args []string
		want polRequest
	}{
		{[]string{"policies"}, polRequest{"GET", "/api/v1/policies", ""}},
		{[]string{"policies", "pending"}, polRequest{"GET", "/api/v1/policies?status=PENDING", ""}},
		{[]string{"policies", "approve", "id-1", "--fleet"}, polRequest{"POST", "/api/v1/policies/id-1/approve", `{"scope":"fleet"}`}},
		{[]string{"policies", "approve", "--host", "h-1", "id-1"}, polRequest{"POST", "/api/v1/policies/id-1/approve", `{"host_id":"h-1","scope":"host"}`}},
		{[]string{"policies", "reject", "id-2", "--host", "h-2"}, polRequest{"POST", "/api/v1/policies/id-2/reject", `{"host_id":"h-2","scope":"host"}`}},
		{[]string{"policies", "reject", "id-2", "--fleet"}, polRequest{"POST", "/api/v1/policies/id-2/reject", `{"scope":"fleet"}`}},
		{[]string{"policies", "approve", "id-1", "id-2", "--fleet"},
			polRequest{"POST", "/api/v1/policies/decide", `{"decision":"approve","ids":["id-1","id-2"],"scope":"fleet"}`}},
		{[]string{"policies", "approve", "id-1", "--seen-hosts", "id-2", "id-3"},
			polRequest{"POST", "/api/v1/policies/decide", `{"decision":"approve","ids":["id-1","id-2","id-3"],"scope":"seen_hosts"}`}},
		{[]string{"policies", "reject", "--seen-hosts", "id-4"},
			polRequest{"POST", "/api/v1/policies/decide", `{"decision":"reject","ids":["id-4"],"scope":"seen_hosts"}`}},
		{[]string{"policies", "delete", "id-3"}, polRequest{"DELETE", "/api/v1/policies/id-3", ""}},
		{[]string{"learning"}, polRequest{"GET", "/api/v1/learning", ""}},
		{[]string{"learning", "start", "--fleet", "--for", "5m"}, polRequest{"PUT", "/api/v1/learning/fleet", `{"duration":"5m"}`}},
		{[]string{"learning", "start", "--host", "h-1", "--until", "2026-11-01T00:00:00Z"}, polRequest{"PUT", "/api/v1/learning/hosts/h-1", `{"ends_at":"2026-11-01T00:00:00Z"}`}},
		{[]string{"learning", "stop", "--host", "h-1"}, polRequest{"DELETE", "/api/v1/learning/hosts/h-1", ""}},
		{[]string{"learning", "stop", "--fleet"}, polRequest{"DELETE", "/api/v1/learning/fleet", ""}},
	}
	for _, c := range cases {
		cli, got := polServer(t)
		if err := cli.run(c.args); err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if len(*got) != 1 || (*got)[0] != c.want {
			t.Errorf("%v: requests %+v, want %+v", c.args, *got, c.want)
		}
	}

	for _, args := range [][]string{
		{"policies", "approve", "id-1"},
		{"policies", "approve", "id-1", "--fleet", "--host", "h"},
		{"policies", "reject", "--fleet"},
		{"policies", "approve", "id-1", "id-2", "--host", "h"},
		{"policies", "approve", "id-1", "--fleet", "--seen-hosts"},
		{"policies", "pending", "--since", "yesterday"},
		{"policies", "pending", "extra"},
		{"learning", "start", "--fleet"},
		{"learning", "start", "--fleet", "--for", "5m", "--until", "2026-11-01T00:00:00Z"},
		{"learning", "start", "--host", "h", "--until", "tomorrow"},
		{"learning", "stop"},
		{"policies", "bogus"},
	} {
		cli, got := polServer(t)
		if err := cli.run(args); err == nil {
			t.Errorf("%v: accepted", args)
		}
		if len(*got) != 0 {
			t.Errorf("%v: sent %+v", args, *got)
		}
	}
}

// pendingServer answers the hosts list, the PENDING list and bulk
// decisions (one of which failed) with fixed data.
func pendingServer(t *testing.T) (*CLI, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/hosts":
			w.Write([]byte(`[{"id":"h-1","hostname":"web-01"},{"id":"h-2","hostname":"db-01"}]`))
		case r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("status") == "PENDING":
			w.Write([]byte(`[
				{"id":"old","learned":{"key":{"event_type":"DLOPEN"},"first_seen":"2026-10-01T00:00:00Z","hosts":["h-1"]}},
				{"id":"bpf-web","learned":{"key":{"event_type":"BPF_LOAD"},"first_seen":"2026-10-11T08:00:00Z","hosts":["h-1"]}},
				{"id":"dl-both","learned":{"key":{"event_type":"DLOPEN"},"first_seen":"2026-10-11T09:00:00Z","hosts":["h-1","h-2"]}}
			]`))
		case r.URL.Path == "/api/v1/policies/decide":
			w.Write([]byte(`{"results":[{"id":"a","ok":true,"entries":[{}]},{"id":"b","ok":false,"error":"not PENDING"}]}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	return &CLI{baseURL: srv.URL, token: "tok", client: srv.Client(), out: &out}, &out
}

// TestCLI_PendingFilters: policies pending filters by first-seen time,
// host (ID or hostname) and event type.
func TestCLI_PendingFilters(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "old bpf-web dl-both"},
		{[]string{"--since", "2026-10-11T00:00:00Z"}, "bpf-web dl-both"},
		{[]string{"--host", "db-01"}, "dl-both"},
		{[]string{"--host", "h-1", "--type", "dlopen"}, "old dl-both"},
		{[]string{"--since", "2026-10-11T08:30:00Z", "--type", "BPF_LOAD"}, ""},
	} {
		cli, out := pendingServer(t)
		if err := cli.run(append([]string{"policies", "pending"}, c.args...)); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		var entries []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
			t.Fatalf("%v: output %q: %v", c.args, out, err)
		}
		var ids []string
		for _, e := range entries {
			ids = append(ids, e.ID)
		}
		if got := strings.Join(ids, " "); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}

// TestCLI_BulkDecisionWithFailuresFails: when any entry of a bulk decision
// was not decided, the command prints the results and fails.
func TestCLI_BulkDecisionWithFailuresFails(t *testing.T) {
	cli, out := pendingServer(t)
	err := cli.run([]string{"policies", "approve", "a", "b", "--fleet"})
	if err == nil || !strings.Contains(err.Error(), "1 of 2 entries not decided") {
		t.Errorf("error %v, want 1 of 2 not decided", err)
	}
	if !strings.Contains(out.String(), "not PENDING") {
		t.Errorf("results not printed: %s", out)
	}
}

// TestParseSince: --since takes an RFC 3339 time, a Go duration or whole
// days, back from now.
func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"2026-10-10T00:00:00Z": time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
		"90m":                  now.Add(-90 * time.Minute),
		"36h":                  now.Add(-36 * time.Hour),
		"7d":                   now.Add(-7 * 24 * time.Hour),
	} {
		if got, err := parseSince(in, now); err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "-5m", "0s", "1.5d", "d"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
