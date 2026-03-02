// Package store provides the PostgreSQL-backed persistence layer for HookMon.
// It manages events, allowlist entries, hosts, and audit logs.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store provides access to the HookMon PostgreSQL database.
type Store struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

// EventFilter defines the criteria for querying events.
type EventFilter struct {
	Limit     int              `json:"limit"`
	Offset    int              `json:"offset"`
	EventType *event.EventType `json:"event_type,omitempty"`
	HostID    string           `json:"host_id,omitempty"`
	Severity  *event.Severity  `json:"severity,omitempty"`
	Since     *time.Time       `json:"since,omitempty"`
	Until     *time.Time       `json:"until,omitempty"`
}

// NewStore creates a new Store connected to PostgreSQL at the given connection string.
// The connection string should be a PostgreSQL DSN, e.g.:
//
//	"postgres://user:pass@localhost:5432/hookmon?sslmode=disable"
func NewStore(ctx context.Context, connString string, logger *zap.Logger) (*Store, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	logger.Info("connected to PostgreSQL", zap.String("host", config.ConnConfig.Host))

	return &Store{
		pool:   pool,
		logger: logger,
	}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
	s.logger.Info("database connection pool closed")
}

// RunMigrations reads embedded SQL migration files and executes them in order.
// Migrations are idempotent (CREATE IF NOT EXISTS) so they are safe to re-run.
func (s *Store) RunMigrations(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}

	// Sort entries by name to guarantee execution order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		s.logger.Info("applying migration", zap.String("file", entry.Name()))

		if _, err := s.pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("execute migration %s: %w", entry.Name(), err)
		}
	}

	s.logger.Info("all migrations applied successfully")
	return nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// InsertEvent persists a HookEvent to the events table.
func (s *Store) InsertEvent(ctx context.Context, ev *event.HookEvent) error {
	bpfJSON, err := nullableJSON(ev.BPFDetail)
	if err != nil {
		return fmt.Errorf("marshal bpf_detail: %w", err)
	}
	preloadJSON, err := nullableJSON(ev.PreloadDetail)
	if err != nil {
		return fmt.Errorf("marshal preload_detail: %w", err)
	}
	shmJSON, err := nullableJSON(ev.SHMDetail)
	if err != nil {
		return fmt.Errorf("marshal shm_detail: %w", err)
	}
	dlopenJSON, err := nullableJSON(ev.DlopenDetail)
	if err != nil {
		return fmt.Errorf("marshal dlopen_detail: %w", err)
	}
	policyJSON, err := nullableJSON(ev.PolicyResult)
	if err != nil {
		return fmt.Errorf("marshal policy_result: %w", err)
	}

	const query = `
		INSERT INTO events (
			id, timestamp, host_id, hostname,
			event_type, severity,
			pid, ppid, uid, gid,
			comm, cmdline, exe_path, exe_hash,
			cgroup_path, container_id, namespace,
			bpf_detail, preload_detail, shm_detail, dlopen_detail,
			policy_result
		) VALUES (
			$1, $2, $3, $4,
			$5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17,
			$18, $19, $20, $21,
			$22
		)`

	_, err = s.pool.Exec(ctx, query,
		ev.ID, ev.Timestamp, ev.HostID, ev.Hostname,
		string(ev.EventType), string(ev.Severity),
		ev.PID, ev.PPID, ev.UID, ev.GID,
		ev.Comm, ev.Cmdline, ev.ExePath, ev.ExeHash,
		ev.CgroupPath, ev.ContainerID, ev.Namespace,
		bpfJSON, preloadJSON, shmJSON, dlopenJSON,
		policyJSON,
	)
	if err != nil {
		return fmt.Errorf("insert event %s: %w", ev.ID, err)
	}

	return nil
}

// QueryEvents retrieves events matching the given filter, ordered by timestamp descending.
func (s *Store) QueryEvents(ctx context.Context, filter EventFilter) ([]*event.HookEvent, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if filter.HostID != "" {
		conditions = append(conditions, fmt.Sprintf("host_id = $%d", argIdx))
		args = append(args, filter.HostID)
		argIdx++
	}
	if filter.EventType != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, string(*filter.EventType))
		argIdx++
	}
	if filter.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, string(*filter.Severity))
		argIdx++
	}
	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *filter.Since)
		argIdx++
	}
	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *filter.Until)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT
			id, timestamp, host_id, hostname,
			event_type, severity,
			pid, ppid, uid, gid,
			comm, cmdline, exe_path, exe_hash,
			cgroup_path, container_id, namespace,
			bpf_detail, preload_detail, shm_detail, dlopen_detail,
			policy_result
		FROM events
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []*event.HookEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate event rows: %w", err)
	}

	return events, nil
}

// scanEvent reads a single event row from the current row cursor.
func scanEvent(rows pgx.Rows) (*event.HookEvent, error) {
	var ev event.HookEvent
	var eventType, severity string
	var bpfJSON, preloadJSON, shmJSON, dlopenJSON, policyJSON []byte

	err := rows.Scan(
		&ev.ID, &ev.Timestamp, &ev.HostID, &ev.Hostname,
		&eventType, &severity,
		&ev.PID, &ev.PPID, &ev.UID, &ev.GID,
		&ev.Comm, &ev.Cmdline, &ev.ExePath, &ev.ExeHash,
		&ev.CgroupPath, &ev.ContainerID, &ev.Namespace,
		&bpfJSON, &preloadJSON, &shmJSON, &dlopenJSON,
		&policyJSON,
	)
	if err != nil {
		return nil, err
	}

	ev.EventType = event.EventType(eventType)
	ev.Severity = event.Severity(severity)

	if len(bpfJSON) > 0 {
		ev.BPFDetail = &event.BPFDetail{}
		if err := json.Unmarshal(bpfJSON, ev.BPFDetail); err != nil {
			return nil, fmt.Errorf("unmarshal bpf_detail: %w", err)
		}
	}
	if len(preloadJSON) > 0 {
		ev.PreloadDetail = &event.PreloadDetail{}
		if err := json.Unmarshal(preloadJSON, ev.PreloadDetail); err != nil {
			return nil, fmt.Errorf("unmarshal preload_detail: %w", err)
		}
	}
	if len(shmJSON) > 0 {
		ev.SHMDetail = &event.SHMDetail{}
		if err := json.Unmarshal(shmJSON, ev.SHMDetail); err != nil {
			return nil, fmt.Errorf("unmarshal shm_detail: %w", err)
		}
	}
	if len(dlopenJSON) > 0 {
		ev.DlopenDetail = &event.DlopenDetail{}
		if err := json.Unmarshal(dlopenJSON, ev.DlopenDetail); err != nil {
			return nil, fmt.Errorf("unmarshal dlopen_detail: %w", err)
		}
	}
	if len(policyJSON) > 0 {
		ev.PolicyResult = &event.PolicyResult{}
		if err := json.Unmarshal(policyJSON, ev.PolicyResult); err != nil {
			return nil, fmt.Errorf("unmarshal policy_result: %w", err)
		}
	}

	return &ev, nil
}

// GetEvent retrieves a single event by ID.
func (s *Store) GetEvent(ctx context.Context, id string) (*event.HookEvent, error) {
	const query = `
		SELECT id, timestamp, host_id, hostname,
			event_type, severity,
			pid, ppid, uid, gid,
			comm, cmdline, exe_path, exe_hash,
			cgroup_path, container_id, namespace,
			bpf_detail, preload_detail, shm_detail, dlopen_detail,
			policy_result
		FROM events WHERE id = $1`

	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("query event: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, fmt.Errorf("event not found: %s", id)
	}
	return scanEvent(rows)
}

// ---------------------------------------------------------------------------
// Hosts (single lookup)
// ---------------------------------------------------------------------------

// GetHost retrieves a single host by ID.
func (s *Store) GetHost(ctx context.Context, id string) (*event.Host, error) {
	const query = `
		SELECT id, hostname, ip_address, agent_version, os_info,
			status, enrolled_at, last_heartbeat, last_event_at
		FROM hosts WHERE id = $1`

	var h event.Host
	var statusStr string
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.AgentVersion, &h.OSInfo,
		&statusStr, &h.EnrolledAt, &h.LastHeartbeat, &h.LastEventAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query host: %w", err)
	}
	h.Status = event.HostStatus(statusStr)
	return &h, nil
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

// GetAllowlist retrieves all allowlist entries.
func (s *Store) GetAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error) {
	const query = `
		SELECT
			id, created_at, created_by, description,
			event_types, exe_hash, exe_path,
			library_hash, library_path,
			prog_name, prog_type, host_pattern,
			uid_range, container_image,
			action, expires, enabled
		FROM allowlist
		ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query allowlist: %w", err)
	}
	defer rows.Close()

	var entries []*event.AllowlistEntry
	for rows.Next() {
		entry, err := scanAllowlistEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan allowlist row: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowlist rows: %w", err)
	}

	return entries, nil
}

// CreateAllowlistEntry inserts a new allowlist entry.
func (s *Store) CreateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error {
	eventTypesJSON, err := json.Marshal(entry.EventTypes)
	if err != nil {
		return fmt.Errorf("marshal event_types: %w", err)
	}

	uidRangeJSON, err := nullableJSON(entry.UIDRange)
	if err != nil {
		return fmt.Errorf("marshal uid_range: %w", err)
	}

	const query = `
		INSERT INTO allowlist (
			id, created_at, created_by, description,
			event_types, exe_hash, exe_path,
			library_hash, library_path,
			prog_name, prog_type, host_pattern,
			uid_range, container_image,
			action, expires, enabled
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11, $12,
			$13, $14,
			$15, $16, $17
		)`

	_, err = s.pool.Exec(ctx, query,
		entry.ID, entry.CreatedAt, entry.CreatedBy, entry.Description,
		eventTypesJSON, entry.ExeHash, entry.ExePath,
		entry.LibraryHash, entry.LibraryPath,
		entry.ProgName, entry.ProgType, entry.HostPattern,
		uidRangeJSON, entry.ContainerImage,
		string(entry.Action), entry.Expires, entry.Enabled,
	)
	if err != nil {
		return fmt.Errorf("insert allowlist entry %s: %w", entry.ID, err)
	}

	return nil
}

// DeleteAllowlistEntry removes an allowlist entry by ID.
func (s *Store) DeleteAllowlistEntry(ctx context.Context, id string) error {
	const query = `DELETE FROM allowlist WHERE id = $1`

	tag, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete allowlist entry %s: %w", id, err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("allowlist entry %s not found", id)
	}

	return nil
}

// scanAllowlistEntry reads a single allowlist row from the current row cursor.
func scanAllowlistEntry(rows pgx.Rows) (*event.AllowlistEntry, error) {
	var entry event.AllowlistEntry
	var action string
	var eventTypesJSON []byte
	var uidRangeJSON []byte

	err := rows.Scan(
		&entry.ID, &entry.CreatedAt, &entry.CreatedBy, &entry.Description,
		&eventTypesJSON, &entry.ExeHash, &entry.ExePath,
		&entry.LibraryHash, &entry.LibraryPath,
		&entry.ProgName, &entry.ProgType, &entry.HostPattern,
		&uidRangeJSON, &entry.ContainerImage,
		&action, &entry.Expires, &entry.Enabled,
	)
	if err != nil {
		return nil, err
	}

	entry.Action = event.PolicyAction(action)

	if len(eventTypesJSON) > 0 {
		if err := json.Unmarshal(eventTypesJSON, &entry.EventTypes); err != nil {
			return nil, fmt.Errorf("unmarshal event_types: %w", err)
		}
	}

	if len(uidRangeJSON) > 0 {
		entry.UIDRange = &event.UIDRange{}
		if err := json.Unmarshal(uidRangeJSON, entry.UIDRange); err != nil {
			return nil, fmt.Errorf("unmarshal uid_range: %w", err)
		}
	}

	return &entry, nil
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

// UpsertHost inserts a host or updates it if it already exists.
func (s *Store) UpsertHost(ctx context.Context, h *event.Host) error {
	const query = `
		INSERT INTO hosts (
			id, hostname, ip_address, agent_version,
			os_info, status, enrolled_at,
			last_heartbeat, last_event_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9
		)
		ON CONFLICT (id) DO UPDATE SET
			hostname       = EXCLUDED.hostname,
			ip_address     = EXCLUDED.ip_address,
			agent_version  = EXCLUDED.agent_version,
			os_info        = EXCLUDED.os_info,
			status         = EXCLUDED.status,
			last_heartbeat = EXCLUDED.last_heartbeat,
			last_event_at  = EXCLUDED.last_event_at`

	_, err := s.pool.Exec(ctx, query,
		h.ID, h.Hostname, h.IPAddress, h.AgentVersion,
		h.OSInfo, string(h.Status), h.EnrolledAt,
		h.LastHeartbeat, h.LastEventAt,
	)
	if err != nil {
		return fmt.Errorf("upsert host %s: %w", h.ID, err)
	}

	return nil
}

// GetHosts retrieves all registered hosts ordered by hostname.
func (s *Store) GetHosts(ctx context.Context) ([]*event.Host, error) {
	const query = `
		SELECT
			id, hostname, ip_address, agent_version,
			os_info, status, enrolled_at,
			last_heartbeat, last_event_at
		FROM hosts
		ORDER BY hostname`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	defer rows.Close()

	var hosts []*event.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host row: %w", err)
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host rows: %w", err)
	}

	return hosts, nil
}

// UpdateHostHeartbeat updates only the last_heartbeat timestamp and sets status to ONLINE.
func (s *Store) UpdateHostHeartbeat(ctx context.Context, hostID string, timestamp time.Time) error {
	const query = `
		UPDATE hosts
		SET last_heartbeat = $1, status = $2
		WHERE id = $3`

	tag, err := s.pool.Exec(ctx, query, timestamp, string(event.HostOnline), hostID)
	if err != nil {
		return fmt.Errorf("update heartbeat for host %s: %w", hostID, err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("host %s not found", hostID)
	}

	return nil
}

// GetStaleHosts returns hosts whose last heartbeat is older than the given threshold
// relative to the current time.
func (s *Store) GetStaleHosts(ctx context.Context, threshold time.Duration) ([]*event.Host, error) {
	cutoff := time.Now().UTC().Add(-threshold)

	const query = `
		SELECT
			id, hostname, ip_address, agent_version,
			os_info, status, enrolled_at,
			last_heartbeat, last_event_at
		FROM hosts
		WHERE last_heartbeat < $1
		ORDER BY last_heartbeat ASC`

	rows, err := s.pool.Query(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query stale hosts: %w", err)
	}
	defer rows.Close()

	var hosts []*event.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan stale host row: %w", err)
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stale host rows: %w", err)
	}

	return hosts, nil
}

// scanHost reads a single host row from the current row cursor.
func scanHost(rows pgx.Rows) (*event.Host, error) {
	var h event.Host
	var status string

	err := rows.Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.AgentVersion,
		&h.OSInfo, &status, &h.EnrolledAt,
		&h.LastHeartbeat, &h.LastEventAt,
	)
	if err != nil {
		return nil, err
	}

	h.Status = event.HostStatus(status)
	return &h, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nullableJSON marshals v to JSON. If v is nil, it returns nil (SQL NULL).
func nullableJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}

	// Handle typed nil pointers: the interface is non-nil but the
	// underlying pointer value is nil.
	switch v.(type) {
	case *event.BPFDetail:
		if v.(*event.BPFDetail) == nil {
			return nil, nil
		}
	case *event.PreloadDetail:
		if v.(*event.PreloadDetail) == nil {
			return nil, nil
		}
	case *event.SHMDetail:
		if v.(*event.SHMDetail) == nil {
			return nil, nil
		}
	case *event.DlopenDetail:
		if v.(*event.DlopenDetail) == nil {
			return nil, nil
		}
	case *event.PolicyResult:
		if v.(*event.PolicyResult) == nil {
			return nil, nil
		}
	case *event.UIDRange:
		if v.(*event.UIDRange) == nil {
			return nil, nil
		}
	}

	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return data, nil
}
