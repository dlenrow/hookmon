// Package store provides the PostgreSQL-backed persistence layer for HookMon.
// It manages events, allowlist entries, hosts, and audit logs.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
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
	// pgx scans TIMESTAMPTZ into the process's local zone by default, so on
	// a host not set to UTC the API would return offsets such as -04:00.
	// Scan every TIMESTAMPTZ into UTC instead; the instant is unchanged.
	config.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name:  "timestamptz",
			OID:   pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		return nil
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

// InsertEvent persists a HookEvent to the events table. In the same
// statement it moves the host's last_event_at forward to the event's
// timestamp, never back: an event that arrives late (an older timestamp)
// leaves it alone. An event whose host is not enrolled is stored all the
// same.
func (s *Store) InsertEvent(ctx context.Context, ev *event.HookEvent) error {
	bpfJSON, err := nullableJSON(ev.BPFDetail)
	if err != nil {
		return fmt.Errorf("marshal bpf_detail: %w", err)
	}
	execInjJSON, err := nullableJSON(ev.ExecInjectionDetail)
	if err != nil {
		return fmt.Errorf("marshal exec_injection_detail: %w", err)
	}
	shmJSON, err := nullableJSON(ev.SHMDetail)
	if err != nil {
		return fmt.Errorf("marshal shm_detail: %w", err)
	}
	dlopenJSON, err := nullableJSON(ev.DlopenDetail)
	if err != nil {
		return fmt.Errorf("marshal dlopen_detail: %w", err)
	}
	linkerJSON, err := nullableJSON(ev.LinkerConfigDetail)
	if err != nil {
		return fmt.Errorf("marshal linker_config_detail: %w", err)
	}
	ptraceJSON, err := nullableJSON(ev.PtraceDetail)
	if err != nil {
		return fmt.Errorf("marshal ptrace_detail: %w", err)
	}
	libIntJSON, err := nullableJSON(ev.LibIntegrityDetail)
	if err != nil {
		return fmt.Errorf("marshal lib_integrity_detail: %w", err)
	}
	elfRpathJSON, err := nullableJSON(ev.ElfRpathDetail)
	if err != nil {
		return fmt.Errorf("marshal elf_rpath_detail: %w", err)
	}
	bpfInvJSON, err := nullableJSON(ev.BPFInventoryDetail)
	if err != nil {
		return fmt.Errorf("marshal bpf_inventory_detail: %w", err)
	}
	policyJSON, err := nullableJSON(ev.PolicyResult)
	if err != nil {
		return fmt.Errorf("marshal policy_result: %w", err)
	}

	// One statement, so the event and the host's last_event_at are written
	// together or not at all. The UPDATE's WHERE is checked again against
	// the latest row version if another insert for the host updated it
	// first, so concurrent events cannot move last_event_at back.
	const query = `
		WITH ins AS (
			INSERT INTO events (
				id, timestamp, host_id, hostname,
				event_type, severity,
				pid, ppid, uid, gid,
				comm, cmdline, exe_path, exe_hash,
				cgroup_path, container_id, namespace,
				bpf_detail, exec_injection_detail, shm_detail, dlopen_detail,
				linker_config_detail, ptrace_detail, lib_integrity_detail,
				elf_rpath_detail, bpf_inventory_detail,
				policy_result
			) VALUES (
				$1, $2, $3, $4,
				$5, $6,
				$7, $8, $9, $10,
				$11, $12, $13, $14,
				$15, $16, $17,
				$18, $19, $20, $21,
				$22, $23, $24,
				$25, $26,
				$27
			)
			RETURNING host_id, timestamp
		)
		UPDATE hosts SET last_event_at = ins.timestamp
		FROM ins
		WHERE hosts.id = ins.host_id
		  AND (hosts.last_event_at IS NULL OR hosts.last_event_at < ins.timestamp)`

	_, err = s.pool.Exec(ctx, query,
		ev.ID, ev.Timestamp, ev.HostID, ev.Hostname,
		string(ev.EventType), string(ev.Severity),
		ev.PID, ev.PPID, ev.UID, ev.GID,
		ev.Comm, ev.Cmdline, ev.ExePath, ev.ExeHash,
		ev.CgroupPath, ev.ContainerID, ev.Namespace,
		bpfJSON, execInjJSON, shmJSON, dlopenJSON,
		linkerJSON, ptraceJSON, libIntJSON,
		elfRpathJSON, bpfInvJSON,
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
			bpf_detail, exec_injection_detail, shm_detail, dlopen_detail,
			linker_config_detail, ptrace_detail, lib_integrity_detail,
			elf_rpath_detail, bpf_inventory_detail,
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
	var bpfJSON, execInjJSON, shmJSON, dlopenJSON []byte
	var linkerJSON, ptraceJSON, libIntJSON, elfRpathJSON, bpfInvJSON, policyJSON []byte

	err := rows.Scan(
		&ev.ID, &ev.Timestamp, &ev.HostID, &ev.Hostname,
		&eventType, &severity,
		&ev.PID, &ev.PPID, &ev.UID, &ev.GID,
		&ev.Comm, &ev.Cmdline, &ev.ExePath, &ev.ExeHash,
		&ev.CgroupPath, &ev.ContainerID, &ev.Namespace,
		&bpfJSON, &execInjJSON, &shmJSON, &dlopenJSON,
		&linkerJSON, &ptraceJSON, &libIntJSON,
		&elfRpathJSON, &bpfInvJSON,
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
	if len(execInjJSON) > 0 {
		ev.ExecInjectionDetail = &event.ExecInjectionDetail{}
		if err := json.Unmarshal(execInjJSON, ev.ExecInjectionDetail); err != nil {
			return nil, fmt.Errorf("unmarshal exec_injection_detail: %w", err)
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
	if len(linkerJSON) > 0 {
		ev.LinkerConfigDetail = &event.LinkerConfigDetail{}
		if err := json.Unmarshal(linkerJSON, ev.LinkerConfigDetail); err != nil {
			return nil, fmt.Errorf("unmarshal linker_config_detail: %w", err)
		}
	}
	if len(ptraceJSON) > 0 {
		ev.PtraceDetail = &event.PtraceDetail{}
		if err := json.Unmarshal(ptraceJSON, ev.PtraceDetail); err != nil {
			return nil, fmt.Errorf("unmarshal ptrace_detail: %w", err)
		}
	}
	if len(libIntJSON) > 0 {
		ev.LibIntegrityDetail = &event.LibIntegrityDetail{}
		if err := json.Unmarshal(libIntJSON, ev.LibIntegrityDetail); err != nil {
			return nil, fmt.Errorf("unmarshal lib_integrity_detail: %w", err)
		}
	}
	if len(elfRpathJSON) > 0 {
		ev.ElfRpathDetail = &event.ElfRpathDetail{}
		if err := json.Unmarshal(elfRpathJSON, ev.ElfRpathDetail); err != nil {
			return nil, fmt.Errorf("unmarshal elf_rpath_detail: %w", err)
		}
	}
	if len(bpfInvJSON) > 0 {
		ev.BPFInventoryDetail = &event.BPFInventoryDetail{}
		if err := json.Unmarshal(bpfInvJSON, ev.BPFInventoryDetail); err != nil {
			return nil, fmt.Errorf("unmarshal bpf_inventory_detail: %w", err)
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

// GetEvent retrieves a single event by ID. A missing event is ErrNotFound
// (wrapped); any other error is a database failure.
func (s *Store) GetEvent(ctx context.Context, id string) (*event.HookEvent, error) {
	const query = `
		SELECT id, timestamp, host_id, hostname,
			event_type, severity,
			pid, ppid, uid, gid,
			comm, cmdline, exe_path, exe_hash,
			cgroup_path, container_id, namespace,
			bpf_detail, exec_injection_detail, shm_detail, dlopen_detail,
			linker_config_detail, ptrace_detail, lib_integrity_detail,
			elf_rpath_detail, bpf_inventory_detail,
			policy_result
		FROM events WHERE id = $1`

	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("query event: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("query event: %w", err)
		}
		return nil, fmt.Errorf("event %s: %w", id, ErrNotFound)
	}
	ev, err := scanEvent(rows)
	if err != nil {
		return nil, fmt.Errorf("scan event: %w", err)
	}
	return ev, nil
}

// ---------------------------------------------------------------------------
// Hosts (single lookup)
// ---------------------------------------------------------------------------

// GetHost retrieves a single host by ID.
func (s *Store) GetHost(ctx context.Context, id string) (*event.Host, error) {
	query := `SELECT ` + hostColumns + ` FROM hosts WHERE id = $1`

	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("query host: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("query host: %w", err)
		}
		return nil, fmt.Errorf("host %s: %w", id, ErrNotFound)
	}
	return scanHost(rows)
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

// hostColumns is the column list scanHost reads, in order.
const hostColumns = `
	id, hostname, ip_address, agent_version,
	os_info, status, enrolled_at,
	last_heartbeat, last_event_at, sensors,
	kernel_release, prev_kernel_release, kernel_changed_at`

// UpsertHost inserts a host or updates it if it already exists. It does not
// touch the sensor snapshot, and never moves last_event_at back: an update
// keeps the later of the stored and the given time.
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
			last_event_at  = GREATEST(hosts.last_event_at, EXCLUDED.last_event_at)`

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

// EnrollHost adds a newly enrolled host. When consumeFingerprint is not
// empty, the enrollment token is single-use: its fingerprint is recorded in
// enrollment_token_uses in the same transaction, and if it is already there
// EnrollHost returns crypto.ErrTokenUsed and adds nothing. The primary key
// makes this safe against concurrent enrollments and server restarts.
func (s *Store) EnrollHost(ctx context.Context, h *event.Host, tokenName, consumeFingerprint string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if consumeFingerprint != "" {
		tag, err := tx.Exec(ctx, `
			INSERT INTO enrollment_token_uses (token_fingerprint, token_name, host_id, used_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (token_fingerprint) DO NOTHING`,
			consumeFingerprint, tokenName, h.ID, h.EnrolledAt,
		)
		if err != nil {
			return fmt.Errorf("record token use: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return hcrypto.ErrTokenUsed
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO hosts (
			id, hostname, ip_address, agent_version,
			os_info, status, enrolled_at,
			last_heartbeat, last_event_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		h.ID, h.Hostname, h.IPAddress, h.AgentVersion,
		h.OSInfo, string(h.Status), h.EnrolledAt,
		h.LastHeartbeat, h.LastEventAt,
	)
	if err != nil {
		return fmt.Errorf("insert host %s: %w", h.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enrollment: %w", err)
	}
	return nil
}

// GetHosts retrieves all registered hosts ordered by hostname.
func (s *Store) GetHosts(ctx context.Context) ([]*event.Host, error) {
	query := `SELECT ` + hostColumns + ` FROM hosts ORDER BY hostname`

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

// UpdateHostHeartbeat records a heartbeat: the receive time, the bus
// version and the sensor snapshot, and sets the host ONLINE. It returns
// ErrNotFound (wrapped) if the host is not enrolled.
func (s *Store) UpdateHostHeartbeat(ctx context.Context, hb *event.HostHeartbeat) error {
	_, err := s.RecordHeartbeat(ctx, hb)
	return err
}

// RecordHeartbeat is UpdateHostHeartbeat, and also returns the host's
// status and last heartbeat from before this one. The read and the update
// are one statement that locks the row, so a heartbeat and the watchdog's
// MarkHostUnresponsive are ordered: either the watchdog sees the new
// heartbeat and leaves the host ONLINE, or the heartbeat sees UNRESPONSIVE
// and the caller raises AGENT_RECOVERED. Each outage is reported once.
func (s *Store) RecordHeartbeat(ctx context.Context, hb *event.HostHeartbeat) (ingestion.HeartbeatChange, error) {
	sensorsJSON, err := json.Marshal(hb.Sensors)
	if err != nil {
		return ingestion.HeartbeatChange{}, fmt.Errorf("marshal sensors: %w", err)
	}
	if hb.Sensors == nil {
		sensorsJSON = nil
	}

	const query = `
		WITH prev AS (
			SELECT id, status, last_heartbeat, kernel_release FROM hosts WHERE id = $6 FOR UPDATE
		)
		UPDATE hosts
		SET last_heartbeat = $1,
			status = $2,
			agent_version = CASE WHEN $3 = '' THEN hosts.agent_version ELSE $3 END,
			sensors = $4,
			prev_kernel_release = CASE WHEN $5 != '' AND $5 != hosts.kernel_release THEN hosts.kernel_release ELSE hosts.prev_kernel_release END,
			kernel_release = CASE WHEN $5 != '' THEN $5 ELSE hosts.kernel_release END,
			kernel_changed_at = CASE WHEN $5 != '' AND $5 != hosts.kernel_release AND hosts.kernel_release != '' THEN $1 ELSE hosts.kernel_changed_at END
		FROM prev
		WHERE hosts.id = prev.id
		RETURNING prev.status, prev.last_heartbeat, prev.kernel_release`

	var prevStatus string
	var prevHeartbeat time.Time
	var prevKernel string
	err = s.pool.QueryRow(ctx, query,
		hb.ReceivedAt, string(event.HostOnline), hb.AgentVersion, sensorsJSON, hb.KernelRelease, hb.HostID,
	).Scan(&prevStatus, &prevHeartbeat, &prevKernel)
	if errors.Is(err, pgx.ErrNoRows) {
		return ingestion.HeartbeatChange{}, fmt.Errorf("host %s: %w", hb.HostID, ErrNotFound)
	}
	if err != nil {
		return ingestion.HeartbeatChange{}, fmt.Errorf("update heartbeat for host %s: %w", hb.HostID, err)
	}
	kernelChanged := hb.KernelRelease != "" && prevKernel != "" && hb.KernelRelease != prevKernel
	return ingestion.HeartbeatChange{
		PrevStatus:        event.HostStatus(prevStatus),
		PrevHeartbeat:     prevHeartbeat,
		PrevKernelRelease: prevKernel,
		KernelChanged:     kernelChanged,
	}, nil
}

// MarkHostUnresponsive sets an ONLINE host UNRESPONSIVE if its last
// heartbeat is still older than staleBefore. It reports whether it changed
// the host, so a heartbeat that lands between the watchdog's query and this
// update keeps the host online and raises no alert.
func (s *Store) MarkHostUnresponsive(ctx context.Context, hostID string, staleBefore time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE hosts SET status = $1
		WHERE id = $2 AND status = $3 AND last_heartbeat < $4`,
		string(event.HostUnresponsive), hostID, string(event.HostOnline), staleBefore,
	)
	if err != nil {
		return false, fmt.Errorf("mark host %s unresponsive: %w", hostID, err)
	}
	return tag.RowsAffected() == 1, nil
}

// GetStaleHosts returns hosts whose last heartbeat is older than the given threshold
// relative to the current time.
func (s *Store) GetStaleHosts(ctx context.Context, threshold time.Duration) ([]*event.Host, error) {
	cutoff := time.Now().UTC().Add(-threshold)

	query := `SELECT ` + hostColumns + `
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

// scanHost reads a single host row, selected with hostColumns, from the
// current row cursor.
func scanHost(rows pgx.Rows) (*event.Host, error) {
	var h event.Host
	var status string
	var sensorsJSON []byte

	err := rows.Scan(
		&h.ID, &h.Hostname, &h.IPAddress, &h.AgentVersion,
		&h.OSInfo, &status, &h.EnrolledAt,
		&h.LastHeartbeat, &h.LastEventAt, &sensorsJSON,
		&h.KernelRelease, &h.PrevKernelRelease, &h.KernelChangedAt,
	)
	if err != nil {
		return nil, err
	}

	h.Status = event.HostStatus(status)
	if len(sensorsJSON) > 0 {
		if err := json.Unmarshal(sensorsJSON, &h.Sensors); err != nil {
			return nil, fmt.Errorf("unmarshal sensors: %w", err)
		}
	}
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
	case *event.ExecInjectionDetail:
		if v.(*event.ExecInjectionDetail) == nil {
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
	case *event.LinkerConfigDetail:
		if v.(*event.LinkerConfigDetail) == nil {
			return nil, nil
		}
	case *event.PtraceDetail:
		if v.(*event.PtraceDetail) == nil {
			return nil, nil
		}
	case *event.LibIntegrityDetail:
		if v.(*event.LibIntegrityDetail) == nil {
			return nil, nil
		}
	case *event.ElfRpathDetail:
		if v.(*event.ElfRpathDetail) == nil {
			return nil, nil
		}
	case *event.BPFInventoryDetail:
		if v.(*event.BPFInventoryDetail) == nil {
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
