package store

// PostgreSQL test for editing allowlist entries (fix plan step 7e, PUT and
// PATCH on /api/v1/policies/{id}). Needs HOOKMON_TEST_PG_DSN.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

func TestUpdateAllowlistEntry(t *testing.T) {
	s, _ := polMigrated(t)
	ctx := context.Background()
	created := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	plain := &event.AllowlistEntry{ID: "plain", CreatedAt: created, CreatedBy: "ops", Description: "before",
		EventTypes: []event.EventType{event.EventBPFLoad}, ExePath: "/usr/bin/a", Action: event.ActionAllow, Enabled: true}
	if err := s.CreateAllowlistEntry(ctx, plain); err != nil {
		t.Fatal(err)
	}
	k := event.LearnedKey{EventType: event.EventDlopen, ExeHash: "sha256:" + strings.Repeat("ab", 32),
		SubjectKind: allowlist.SubjectLibraryPath, Subject: "/opt/x.so"}
	sighting, err := s.RecordCandidate(ctx, k, "/usr/bin/app", "learned", "host-a", "", created)
	if err != nil {
		t.Fatal(err)
	}
	pendingID := sighting.ID
	learnedID := "learned"
	if err := s.CreateAllowlistEntry(ctx, &event.AllowlistEntry{ID: learnedID, CreatedAt: created, CreatedBy: LearningCreator,
		Action: event.ActionAllow, Enabled: true, HostID: "host-b",
		Learned: &event.Learned{Key: k, Occurrences: 7, FirstSeen: created, LastSeen: created, Hosts: []string{"host-b"}}}); err != nil {
		t.Fatal(err)
	}

	// Every editable field is written; the rest is kept.
	pt := uint32(5)
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	edit := &event.AllowlistEntry{ID: "plain", CreatedAt: time.Now(), CreatedBy: "mallory", Status: event.StatusRejected,
		Description: "after", EventTypes: []event.EventType{event.EventBPFLoad, event.EventBPFAttach},
		ExeHash: "sha256:" + strings.Repeat("cd", 32), ExePath: "/usr/bin/b",
		LibraryHash: "sha256:" + strings.Repeat("ef", 32), LibraryPath: "/opt/*.so",
		ProgName: "p*", ProgType: &pt, ProgHash: "a04f5eef06a7f555", HostPattern: "web-*",
		UIDRange: &event.UIDRange{Min: 1, Max: 2}, ContainerImage: "c*", AllowedRpaths: []string{"/opt/lib"}, HostID: "host-a",
		Action: event.ActionDeny, Expires: &exp, Enabled: false}
	if err := s.UpdateAllowlistEntry(ctx, edit); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAllowlistEntry(ctx, "plain")
	if err != nil {
		t.Fatal(err)
	}
	polUTC(got)
	want := *edit
	want.CreatedAt, want.CreatedBy, want.Status = created, "ops", event.StatusApproved
	if !reflect.DeepEqual(got, &want) {
		t.Errorf("after update:\n got %+v\nwant %+v", got, &want)
	}

	// Clearing: nil and empty values are stored as empty.
	cleared := &event.AllowlistEntry{ID: "plain", Action: event.ActionAlert, Enabled: true}
	if err := s.UpdateAllowlistEntry(ctx, cleared); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAllowlistEntry(ctx, "plain")
	if got.Expires != nil || got.ProgType != nil || got.UIDRange != nil || len(got.EventTypes) != 0 || got.AllowedRpaths != nil ||
		got.HostID != "" || got.Description != "" || got.Action != event.ActionAlert || !got.Enabled {
		t.Errorf("after clearing: %+v", got)
	}

	// A learned entry keeps its key, counts and hosts.
	if err := s.UpdateAllowlistEntry(ctx, &event.AllowlistEntry{ID: learnedID, Description: "edited", Action: event.ActionAllow, HostID: "host-b"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAllowlistEntry(ctx, learnedID)
	if got.Learned == nil || got.Learned.Key != k || got.Learned.Occurrences != 7 || got.Description != "edited" || got.Enabled ||
		got.CreatedBy != LearningCreator {
		t.Errorf("learned entry after update: %+v %+v", got, got.Learned)
	}

	if err := s.UpdateAllowlistEntry(ctx, &event.AllowlistEntry{ID: pendingID, Action: event.ActionAllow}); !errors.Is(err, ErrPending) {
		t.Errorf("PENDING entry: %v, want ErrPending", err)
	}
	if p, _ := s.GetAllowlistEntry(ctx, pendingID); p.Status != event.StatusPending || p.Action != event.ActionAlert {
		t.Errorf("PENDING entry changed: %+v", p)
	}
	if err := s.UpdateAllowlistEntry(ctx, &event.AllowlistEntry{ID: "nope", Action: event.ActionAllow}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing entry: %v, want ErrNotFound", err)
	}
}
