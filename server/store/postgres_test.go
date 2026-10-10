package store

// These tests need a PostgreSQL the test can create schemas in. Set
// HOOKMON_TEST_PG_DSN, for example
//
//	HOOKMON_TEST_PG_DSN='postgres://postgres:pw@127.0.0.1:55432/postgres?sslmode=disable'
//
// Without it they skip. Each test runs in its own schema, dropped afterwards.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// secStore connects a Store to a fresh schema, or skips the test. It also
// returns the schema's DSN, for a second Store on the same schema.
func secStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("HOOKMON_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("HOOKMON_TEST_PG_DSN is not set; skipping the PostgreSQL store test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	schema := "sec_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to HOOKMON_TEST_PG_DSN: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "search_path=" + schema
	} else {
		dsn += " search_path=" + schema
	}
	return secOpen(t, dsn), dsn
}

func secOpen(t *testing.T, dsn string) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := NewStore(ctx, dsn, zap.NewNop())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// secApplyBefore applies the embedded migrations named before limit, as a
// database created by an older server would have them.
func secApplyBefore(t *testing.T, s *Store, limit string) {
	t.Helper()
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.Name() >= limit {
			continue
		}
		data, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(context.Background(), string(data)); err != nil {
			t.Fatalf("apply %s: %v", e.Name(), err)
		}
	}
}

// secColumnTypes returns the data type of each uint32 column.
func secColumnTypes(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `
		SELECT table_name || '.' || column_name, data_type
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND ((table_name = 'events' AND column_name IN ('pid', 'ppid', 'uid', 'gid'))
		    OR (table_name = 'allowlist' AND column_name = 'prog_type'))`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var col, typ string
		if err := rows.Scan(&col, &typ); err != nil {
			t.Fatal(err)
		}
		out[col] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func secUnknownUIDEvent(id string) *event.HookEvent {
	return &event.HookEvent{
		ID:        id,
		Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		HostID:    "host-a",
		Hostname:  "host-a",
		EventType: event.EventExecInjection,
		Severity:  event.SeverityAlert,
		PID:       math.MaxUint32,
		PPID:      math.MaxUint32,
		UID:       math.MaxUint32, // "unknown" since step 4
		GID:       math.MaxUint32,
		Comm:      "sh",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			TargetBinary: "/usr/bin/true",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
}

// TestMigration_UnknownUIDStored starts from the schema a server before
// this change created (migrations 001-004, where pid, ppid, uid and gid are
// INTEGER), shows that an event with UID 4294967295 is rejected there, then
// starts a new Store on the same schema, as an upgraded server would, and
// runs the migrations: existing rows survive, the columns are BIGINT, and
// the same event is stored and read back unchanged. Running the
// migrations again changes nothing.
func TestMigration_UnknownUIDStored(t *testing.T) {
	old, dsn := secStore(t)
	ctx := context.Background()

	secApplyBefore(t, old, "005")
	for col, typ := range secColumnTypes(t, old) {
		if typ != "integer" {
			t.Fatalf("before 005: %s is %s, want integer", col, typ)
		}
	}
	oldEvt := &event.HookEvent{
		ID: "old-evt", Timestamp: time.Now().UTC().Truncate(time.Microsecond), HostID: "host-a", Hostname: "host-a",
		EventType: event.EventBPFLoad, Severity: event.SeverityWarn, PID: 42, PPID: 1, UID: 1000, GID: 1000,
	}
	if err := old.InsertEvent(ctx, oldEvt); err != nil {
		t.Fatalf("insert into the old schema: %v", err)
	}
	if err := old.InsertEvent(ctx, secUnknownUIDEvent("rejected")); err == nil {
		t.Fatal("the old INTEGER schema stored UID 4294967295; this test no longer shows the bug")
	}
	// The old server stops. (pgx caches each statement's parameter types
	// per connection, so the old pool would keep encoding int4.)
	old.Close()

	s := secOpen(t, dsn)
	if err := s.RunMigrations(ctx); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	types := secColumnTypes(t, s)
	if len(types) != 5 {
		t.Fatalf("columns found: %v", types)
	}
	for col, typ := range types {
		if typ != "bigint" {
			t.Errorf("after 005: %s is %s, want bigint", col, typ)
		}
	}

	got, err := s.GetEvent(ctx, "old-evt")
	if err != nil {
		t.Fatalf("existing event after migration: %v", err)
	}
	if got.PID != 42 || got.UID != 1000 || got.GID != 1000 || got.PPID != 1 {
		t.Errorf("existing event changed: %+v", got)
	}

	want := secUnknownUIDEvent("unknown-uid")
	if err := s.InsertEvent(ctx, want); err != nil {
		t.Fatalf("insert UID 4294967295: %v", err)
	}
	got, err = s.GetEvent(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != math.MaxUint32 || got.PID != math.MaxUint32 || got.PPID != math.MaxUint32 || got.GID != math.MaxUint32 {
		t.Errorf("read back pid=%d ppid=%d uid=%d gid=%d, want 4294967295 each", got.PID, got.PPID, got.UID, got.GID)
	}
	if got.ExecInjectionDetail == nil || got.ExecInjectionDetail.LibraryPath != "/tmp/evil.so" {
		t.Errorf("exec injection detail: %+v", got.ExecInjectionDetail)
	}
	listed, err := s.QueryEvents(ctx, EventFilter{HostID: "host-a", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Errorf("QueryEvents: %d events, want 2", len(listed))
	}

	// prog_type is a uint32 too.
	pt := uint32(math.MaxUint32)
	entry := &event.AllowlistEntry{
		ID: "al-1", CreatedAt: time.Now().UTC(), EventTypes: []event.EventType{event.EventBPFLoad},
		ProgType: &pt, Action: event.ActionAllow, Enabled: true,
	}
	if err := s.CreateAllowlistEntry(ctx, entry); err != nil {
		t.Fatalf("allowlist entry with prog_type 4294967295: %v", err)
	}
	entries, err := s.GetAllowlist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ProgType == nil || *entries[0].ProgType != math.MaxUint32 {
		t.Errorf("allowlist read back: %+v", entries)
	}

	if err := s.RunMigrations(ctx); err != nil {
		t.Fatalf("RunMigrations again: %v", err)
	}
	if got, err := s.GetEvent(ctx, want.ID); err != nil || got.UID != math.MaxUint32 {
		t.Errorf("after a second RunMigrations: %+v, %v", got, err)
	}
}

// TestMigration_FreshDatabase: a new database gets BIGINT columns from the
// full migration set.
func TestMigration_FreshDatabase(t *testing.T) {
	s, _ := secStore(t)
	if err := s.RunMigrations(context.Background()); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	for col, typ := range secColumnTypes(t, s) {
		if typ != "bigint" {
			t.Errorf("%s is %s, want bigint", col, typ)
		}
	}
	if err := s.InsertEvent(context.Background(), secUnknownUIDEvent("fresh")); err != nil {
		t.Fatalf("insert UID 4294967295: %v", err)
	}
}
