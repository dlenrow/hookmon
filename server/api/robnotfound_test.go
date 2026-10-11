package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/dlenrow/hookmon/pkg/event"
)

// robFailingStore fails every single-row read the way an unreachable
// database does: with an error that is not store.ErrNotFound.
type robFailingStore struct {
	*polStore
}

var robDBDown = errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")

func (robFailingStore) GetEvent(context.Context, string) (*event.HookEvent, error) {
	return nil, robDBDown
}
func (robFailingStore) GetHost(context.Context, string) (*event.Host, error) {
	return nil, robDBDown
}
func (robFailingStore) GetAllowlistEntry(context.Context, string) (*event.AllowlistEntry, error) {
	return nil, robDBDown
}

// TestSingleRowReads_NotFoundVersusFailure: a missing event, host or
// policy is 404; a store failure on the same request is 500, never 404.
func TestSingleRowReads_NotFoundVersusFailure(t *testing.T) {
	requests := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/events/nope", ""},
		{http.MethodGet, "/api/v1/hosts/nope", ""},
		{http.MethodPost, "/api/v1/events/nope/allowlist", `{"scope":"fleet"}`},
		{http.MethodPatch, "/api/v1/policies/nope", `{"enabled":false}`},
	}

	missing := polRouter(newPolStore(), &polReloader{})
	failing := polRouter(robFailingStore{newPolStore()}, &polReloader{})
	for _, r := range requests {
		name := r.method + " " + r.path
		if code, body := polDo(t, missing, r.method, r.path, r.body); code != http.StatusNotFound {
			t.Errorf("%s, row missing: %d %s, want 404", name, code, body)
		}
		code, body := polDo(t, failing, r.method, r.path, r.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s, store failing: %d %s, want 500", name, code, body)
		}
		if strings.Contains(body, "connection refused") {
			t.Errorf("%s: the store error reached the client: %s", name, body)
		}
	}
}
