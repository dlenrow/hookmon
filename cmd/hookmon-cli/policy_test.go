package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
