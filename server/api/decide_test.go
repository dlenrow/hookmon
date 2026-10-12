package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// decideResponse is the body of a /policies/decide answer.
type decideResponse struct {
	Results []struct {
		ID      string                  `json:"id"`
		OK      bool                    `json:"ok"`
		Entries []*event.AllowlistEntry `json:"entries"`
		Error   string                  `json:"error"`
	} `json:"results"`
}

// TestDecidePolicies_Bulk: several PENDING entries are decided in one call
// with one reload; an ID that is not PENDING or does not exist fails alone.
func TestDecidePolicies_Bulk(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	st.entries = []*event.AllowlistEntry{
		{ID: "p1", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending},
		{ID: "p2", Action: event.ActionAlert, Enabled: true, Status: event.StatusPending},
		{ID: "a1", Action: event.ActionAllow, Enabled: true, Status: event.StatusApproved},
	}
	h := polRouter(st, rl)

	code, body := polDo(t, h, http.MethodPost, "/api/v1/policies/decide",
		`{"ids":["p1","a1","nope","p2"],"decision":"approve","scope":"fleet"}`)
	if code != http.StatusOK {
		t.Fatalf("decide: %d %s", code, body)
	}
	var resp decideResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range resp.Results {
		got = append(got, fmt.Sprintf("%s:%v", r.ID, r.OK))
		if r.OK && (len(r.Entries) != 1 || r.Entries[0].Status != event.StatusApproved || r.Error != "") {
			t.Errorf("%s: entries %+v error %q", r.ID, r.Entries, r.Error)
		}
		if !r.OK && (r.Error == "" || r.Entries != nil) {
			t.Errorf("%s: failed without an error, or with entries", r.ID)
		}
	}
	if strings.Join(got, " ") != "p1:true a1:false nope:false p2:true" {
		t.Errorf("results %v", got)
	}
	if !strings.Contains(resp.Results[1].Error, "not PENDING") || !strings.Contains(resp.Results[2].Error, "not found") {
		t.Errorf("errors: %q, %q", resp.Results[1].Error, resp.Results[2].Error)
	}
	if rl.n() != 1 {
		t.Errorf("reloads: %d, want 1", rl.n())
	}
	if want := "[p1 a1 nope p2] APPROVED fleet"; len(st.bulk) != 1 || st.bulk[0] != want {
		t.Errorf("store calls %q, want %q", st.bulk, want)
	}

	// Reject, for the hosts each entry was seen on. Nothing left to decide:
	// no reload.
	if code, body := polDo(t, h, http.MethodPost, "/api/v1/policies/decide",
		`{"ids":["p1"],"decision":"reject","scope":"seen_hosts"}`); code != http.StatusOK || !strings.Contains(body, `"ok":false`) {
		t.Errorf("decided entry again: %d %s", code, body)
	}
	if st.bulk[1] != "[p1] REJECTED seen_hosts" || rl.n() != 1 {
		t.Errorf("store call %q, reloads %d", st.bulk[1], rl.n())
	}

	// A store failure is a 500 and changes nothing.
	st.decideErr = errors.New("db down")
	if code, _ := polDo(t, h, http.MethodPost, "/api/v1/policies/decide",
		`{"ids":["p2"],"decision":"approve","scope":"fleet"}`); code != http.StatusInternalServerError || rl.n() != 1 {
		t.Errorf("store failure: %d, reloads %d", code, rl.n())
	}
}

// TestDecidePolicies_BadRequests: a malformed body is a 400 and reaches
// neither the store nor the policy.
func TestDecidePolicies_BadRequests(t *testing.T) {
	st, rl := newPolStore(), &polReloader{}
	h := polRouter(st, rl)
	many := make([]string, MaxDecideIDs+1)
	for i := range many {
		many[i] = fmt.Sprintf("%q", fmt.Sprintf("id-%d", i))
	}
	for name, body := range map[string]string{
		"not JSON":      `nope`,
		"no ids":        `{"decision":"approve","scope":"fleet"}`,
		"empty ids":     `{"ids":[],"decision":"approve","scope":"fleet"}`,
		"empty id":      `{"ids":["p1",""],"decision":"approve","scope":"fleet"}`,
		"too many":      `{"ids":[` + strings.Join(many, ",") + `],"decision":"approve","scope":"fleet"}`,
		"bad decision":  `{"ids":["p1"],"decision":"allow","scope":"fleet"}`,
		"bad scope":     `{"ids":["p1"],"decision":"approve","scope":"host"}`,
		"no scope":      `{"ids":["p1"],"decision":"approve"}`,
		"unknown field": `{"ids":["p1"],"decision":"approve","scope":"fleet","host_id":"h"}`,
	} {
		if code, resp := polDo(t, h, http.MethodPost, "/api/v1/policies/decide", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, resp)
		}
	}
	if len(st.bulk) != 0 || rl.n() != 0 {
		t.Errorf("bad requests reached the store (%v) or reloaded (%d)", st.bulk, rl.n())
	}
}
