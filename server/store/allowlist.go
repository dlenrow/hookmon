package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

var (
	// ErrNotFound is returned (wrapped) when a row the call names does not exist.
	ErrNotFound = errors.New("not found")
	// ErrNotPending is returned when approving or rejecting an entry that is
	// not a PENDING candidate.
	ErrNotPending = errors.New("allowlist entry is not PENDING")
	// ErrConflict is returned (wrapped) when a write would duplicate a
	// unique key, such as an allowlist entry ID that is already taken.
	ErrConflict = errors.New("already exists")
)

// pgUniqueViolation is PostgreSQL's SQLSTATE for unique_violation.
const pgUniqueViolation = "23505"

// isUniqueViolation reports whether err is a unique-key violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// LearningCreator is the created_by of entries learning mode creates.
const LearningCreator = "learning-mode"

// allowlistColumns is the column list scanAllowlistEntry reads, in order.
const allowlistColumns = `
	id, created_at, created_by, description,
	event_types, exe_hash, exe_path,
	library_hash, library_path,
	prog_name, prog_type, prog_hash, host_pattern,
	uid_range, container_image,
	allowed_rpaths, host_id,
	action, expires, enabled, status,
	learned_key, learned_exe_path, occurrences, first_seen, last_seen, seen_hosts,
	first_event_id`

// execer is a pool or a transaction.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

// GetAllowlist retrieves all allowlist entries, whatever their status.
func (s *Store) GetAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error) {
	return s.QueryAllowlist(ctx)
}

// GetDecidedAllowlist retrieves the entries the policy engine matches:
// APPROVED and REJECTED. PENDING candidates never match.
func (s *Store) GetDecidedAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error) {
	return s.QueryAllowlist(ctx, event.StatusApproved, event.StatusRejected)
}

// QueryAllowlist retrieves the allowlist entries with any of the given
// statuses, or every entry when none is given, newest first.
func (s *Store) QueryAllowlist(ctx context.Context, statuses ...event.EntryStatus) ([]*event.AllowlistEntry, error) {
	query := `SELECT ` + allowlistColumns + ` FROM allowlist`
	var args []any
	if len(statuses) > 0 {
		names := make([]string, len(statuses))
		for i, st := range statuses {
			names[i] = string(st)
		}
		query += ` WHERE status = ANY($1)`
		args = append(args, names)
	}
	query += ` ORDER BY created_at DESC, id`

	rows, err := s.pool.Query(ctx, query, args...)
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

// GetAllowlistEntry retrieves one entry by ID.
func (s *Store) GetAllowlistEntry(ctx context.Context, id string) (*event.AllowlistEntry, error) {
	return getAllowlistEntry(ctx, s.pool, id, "")
}

// querier is a pool or a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func getAllowlistEntry(ctx context.Context, q querier, id, suffix string) (*event.AllowlistEntry, error) {
	rows, err := q.Query(ctx, `SELECT `+allowlistColumns+` FROM allowlist WHERE id = $1`+suffix, id)
	if err != nil {
		return nil, fmt.Errorf("query allowlist entry: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("query allowlist entry: %w", err)
		}
		return nil, fmt.Errorf("allowlist entry %s: %w", id, ErrNotFound)
	}
	return scanAllowlistEntry(rows)
}

// CreateAllowlistEntry inserts a new allowlist entry. An empty status is
// stored as APPROVED. An ID that is already taken is ErrConflict (wrapped).
func (s *Store) CreateAllowlistEntry(ctx context.Context, entry *event.AllowlistEntry) error {
	if entry.Status == "" {
		entry.Status = event.StatusApproved
	}
	return insertAllowlistEntry(ctx, s.pool, entry)
}

func insertAllowlistEntry(ctx context.Context, x execer, entry *event.AllowlistEntry) error {
	eventTypesJSON, err := json.Marshal(entry.EventTypes)
	if err != nil {
		return fmt.Errorf("marshal event_types: %w", err)
	}
	if entry.EventTypes == nil {
		eventTypesJSON = []byte("[]")
	}

	uidRangeJSON, err := nullableJSON(entry.UIDRange)
	if err != nil {
		return fmt.Errorf("marshal uid_range: %w", err)
	}

	var allowedRpathsJSON []byte
	if len(entry.AllowedRpaths) > 0 {
		allowedRpathsJSON, err = json.Marshal(entry.AllowedRpaths)
		if err != nil {
			return fmt.Errorf("marshal allowed_rpaths: %w", err)
		}
	}

	var (
		candidateKey string
		learnedKey   []byte
		exePath      string
		occurrences  int64
		firstSeen    *time.Time
		lastSeen     *time.Time
		hosts        = []string{}
		firstEventID string
	)
	if l := entry.Learned; l != nil {
		candidateKey = allowlist.KeyHash(l.Key)
		if learnedKey, err = json.Marshal(l.Key); err != nil {
			return fmt.Errorf("marshal learned_key: %w", err)
		}
		exePath, occurrences, firstEventID = l.ExePath, l.Occurrences, l.FirstEventID
		if !l.FirstSeen.IsZero() {
			firstSeen = &l.FirstSeen
		}
		if !l.LastSeen.IsZero() {
			lastSeen = &l.LastSeen
		}
		if l.Hosts != nil {
			hosts = l.Hosts
		}
	}

	_, err = x.Exec(ctx, `
		INSERT INTO allowlist (
			id, created_at, created_by, description,
			event_types, exe_hash, exe_path,
			library_hash, library_path,
			prog_name, prog_type, prog_hash, host_pattern,
			uid_range, container_image,
			allowed_rpaths, host_id,
			action, expires, enabled, status,
			candidate_key, learned_key, learned_exe_path,
			occurrences, first_seen, last_seen, seen_hosts,
			first_event_id
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11, $12, $13,
			$14, $15,
			$16, $17,
			$18, $19, $20, $21,
			$22, $23, $24,
			$25, $26, $27, $28,
			$29
		)`,
		entry.ID, entry.CreatedAt, entry.CreatedBy, entry.Description,
		eventTypesJSON, entry.ExeHash, entry.ExePath,
		entry.LibraryHash, entry.LibraryPath,
		entry.ProgName, entry.ProgType, entry.ProgHash, entry.HostPattern,
		uidRangeJSON, entry.ContainerImage,
		allowedRpathsJSON, entry.HostID,
		string(entry.Action), entry.Expires, entry.Enabled, string(entry.Status),
		candidateKey, learnedKey, exePath,
		occurrences, firstSeen, lastSeen, hosts,
		firstEventID,
	)
	if isUniqueViolation(err) {
		return fmt.Errorf("allowlist entry %s: %w", entry.ID, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("insert allowlist entry %s: %w", entry.ID, err)
	}
	return nil
}

// DeleteAllowlistEntry removes an allowlist entry by ID.
func (s *Store) DeleteAllowlistEntry(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM allowlist WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete allowlist entry %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("allowlist entry %s: %w", id, ErrNotFound)
	}
	return nil
}

// RecordCandidate records an unmatched event's key as a new hook: the
// PENDING entry for the key. The first event of a key creates the entry
// and is recorded as its first event (eventID); each later one adds to its
// occurrence count, widens its first and last seen times, and adds the host
// to its hosts. The sighting says which happened.
//
// When an APPROVED or REJECTED entry for the key is already in force for
// the fleet or for this host (the policy engine had not reloaded it yet),
// nothing is recorded: the sighting's ID is "", and its DecidedAction is
// that entry's action (ALERT before ALLOW when both apply).
func (s *Store) RecordCandidate(ctx context.Context, key event.LearnedKey, exePath, description, hostID, eventID string, seen time.Time) (event.CandidateSighting, error) {
	var sighting event.CandidateSighting
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return sighting, fmt.Errorf("marshal learned_key: %w", err)
	}
	eventTypesJSON, err := json.Marshal(allowlist.EventTypesFor(key))
	if err != nil {
		return sighting, fmt.Errorf("marshal event_types: %w", err)
	}
	candidateKey := allowlist.KeyHash(key)

	// xmax is 0 on a row this statement inserted, and set on one it updated.
	err = s.pool.QueryRow(ctx, `
		INSERT INTO allowlist (
			id, created_at, created_by, description, event_types,
			action, enabled, status,
			candidate_key, learned_key, learned_exe_path,
			occurrences, first_seen, last_seen, seen_hosts,
			first_event_id
		)
		SELECT $1, NOW(), $2, $3, $4,
			'ALERT', TRUE, 'PENDING',
			$5, $6, $7,
			1, $8, $8, ARRAY[$9::TEXT],
			$10
		WHERE NOT EXISTS (
			SELECT 1 FROM allowlist
			WHERE candidate_key = $5 AND status <> 'PENDING' AND enabled
			  AND host_id IN ('', $9::TEXT)
			  AND (expires IS NULL OR expires > NOW())
		)
		ON CONFLICT (candidate_key) WHERE status = 'PENDING' DO UPDATE SET
			occurrences = allowlist.occurrences + 1,
			first_seen  = LEAST(allowlist.first_seen, EXCLUDED.first_seen),
			last_seen   = GREATEST(allowlist.last_seen, EXCLUDED.last_seen),
			seen_hosts  = CASE WHEN $9::TEXT = ANY(allowlist.seen_hosts) THEN allowlist.seen_hosts
			                   ELSE array_append(allowlist.seen_hosts, $9::TEXT) END
		RETURNING id, (xmax = 0)`,
		uuid.New().String(), LearningCreator, description, eventTypesJSON,
		candidateKey, keyJSON, exePath,
		seen, hostID,
		eventID,
	).Scan(&sighting.ID, &sighting.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.decidedSighting(ctx, candidateKey, hostID)
	}
	if err != nil {
		return event.CandidateSighting{}, fmt.Errorf("record candidate: %w", err)
	}
	return sighting, nil
}

// decidedSighting is RecordCandidate's answer when a decided entry for the
// key is in force on hostID: the most restrictive such entry's action.
func (s *Store) decidedSighting(ctx context.Context, candidateKey, hostID string) (event.CandidateSighting, error) {
	var action string
	err := s.pool.QueryRow(ctx, `
		SELECT action FROM allowlist
		WHERE candidate_key = $1 AND status <> 'PENDING' AND enabled
		  AND host_id IN ('', $2::TEXT)
		  AND (expires IS NULL OR expires > NOW())
		ORDER BY (action = 'ALLOW'), id
		LIMIT 1`, candidateKey, hostID).Scan(&action)
	if errors.Is(err, pgx.ErrNoRows) {
		// The entry went away between the two statements. Keep the event.
		return event.CandidateSighting{DecidedAction: event.ActionAlert}, nil
	}
	if err != nil {
		return event.CandidateSighting{}, fmt.Errorf("read decided entry: %w", err)
	}
	return event.CandidateSighting{DecidedAction: event.PolicyAction(action)}, nil
}

// Decision scopes for DecideCandidates.
const (
	// ScopeFleet decides an entry for every host.
	ScopeFleet = "fleet"
	// ScopeSeenHosts decides an entry for each host it was seen on, and no
	// other.
	ScopeSeenHosts = "seen_hosts"
)

// decisionAction is the action an entry takes when it is approved
// (ALLOW) or rejected (ALERT).
func decisionAction(decision event.EntryStatus) (event.PolicyAction, error) {
	switch decision {
	case event.StatusApproved:
		return event.ActionAllow, nil
	case event.StatusRejected:
		return event.ActionAlert, nil
	}
	return "", fmt.Errorf("decision must be APPROVED or REJECTED, not %q", decision)
}

// DecideCandidate approves (decision APPROVED, action ALLOW) or rejects
// (decision REJECTED, action ALERT) the PENDING entry id.
//
// With hostID empty the decision is for the fleet: the entry itself
// changes status and applies on every host. With a host ID, a new entry
// with the same key is created for that host alone, and the host is taken
// off the PENDING entry's hosts; the PENDING entry is deleted when no host
// is left. It returns the entry now in force.
func (s *Store) DecideCandidate(ctx context.Context, id string, decision event.EntryStatus, hostID string) (*event.AllowlistEntry, error) {
	action, err := decisionAction(decision)
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin decision: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	pending, err := getAllowlistEntry(ctx, tx, id, " FOR UPDATE")
	if err != nil {
		return nil, err
	}
	if pending.Status != event.StatusPending {
		return nil, fmt.Errorf("allowlist entry %s is %s: %w", id, pending.Status, ErrNotPending)
	}

	var hosts []string
	if hostID != "" {
		hosts = []string{hostID}
	}
	decided, err := decideInTx(ctx, tx, pending, decision, action, hosts)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit decision: %w", err)
	}
	return decided[0], nil
}

// CandidateDecision is the outcome of DecideCandidates for one ID: the
// entries now in force, or why the ID was not decided.
type CandidateDecision struct {
	ID      string
	Entries []*event.AllowlistEntry
	// Err wraps ErrNotFound or ErrNotPending, or says the ID was repeated
	// or (for ScopeSeenHosts) has no hosts. Nil when the ID was decided.
	Err error
}

// DecideCandidates approves or rejects several PENDING entries in one
// transaction, in the order given. With ScopeFleet each entry is decided
// for every host; with ScopeSeenHosts one entry is created for each host
// the PENDING entry was seen on, and the PENDING entry is deleted. An ID
// that does not exist, is not PENDING, or repeats an earlier ID gets its
// own error, and the others still apply. A database error fails the whole
// call, and nothing changes.
func (s *Store) DecideCandidates(ctx context.Context, ids []string, decision event.EntryStatus, scope string) ([]CandidateDecision, error) {
	action, err := decisionAction(decision)
	if err != nil {
		return nil, err
	}
	if scope != ScopeFleet && scope != ScopeSeenHosts {
		return nil, fmt.Errorf("scope must be %q or %q, not %q", ScopeFleet, ScopeSeenHosts, scope)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin decisions: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	// Lock every row up front, in ID order, so two concurrent calls over
	// the same entries cannot deadlock.
	rows, err := tx.Query(ctx, `SELECT `+allowlistColumns+` FROM allowlist WHERE id = ANY($1) ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return nil, fmt.Errorf("lock allowlist entries: %w", err)
	}
	found := make(map[string]*event.AllowlistEntry, len(ids))
	for rows.Next() {
		entry, err := scanAllowlistEntry(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan allowlist row: %w", err)
		}
		found[entry.ID] = entry
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lock allowlist entries: %w", err)
	}

	out := make([]CandidateDecision, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		d := CandidateDecision{ID: id}
		pending := found[id]
		var hosts []string
		switch {
		case seen[id]:
			d.Err = fmt.Errorf("allowlist entry %s is named more than once", id)
		case pending == nil:
			d.Err = fmt.Errorf("allowlist entry %s: %w", id, ErrNotFound)
		case pending.Status != event.StatusPending:
			d.Err = fmt.Errorf("allowlist entry %s is %s: %w", id, pending.Status, ErrNotPending)
		case scope == ScopeSeenHosts:
			if pending.Learned != nil {
				hosts = pending.Learned.Hosts
			}
			if len(hosts) == 0 {
				d.Err = fmt.Errorf("allowlist entry %s has no hosts recorded; decide it for the fleet", id)
			}
		}
		seen[id] = true
		if d.Err == nil {
			if d.Entries, err = decideInTx(ctx, tx, pending, decision, action, hosts); err != nil {
				return nil, err
			}
		}
		out = append(out, d)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit decisions: %w", err)
	}
	return out, nil
}

// decideInTx decides a PENDING entry locked in tx. With hosts empty the
// decision is for the fleet: the entry itself changes status. Otherwise one
// entry with the same key is created for each host, the hosts are taken off
// the PENDING entry, and the PENDING entry is deleted when no host is left.
// It returns the entries now in force.
func decideInTx(ctx context.Context, tx pgx.Tx, pending *event.AllowlistEntry, decision event.EntryStatus, action event.PolicyAction, hosts []string) ([]*event.AllowlistEntry, error) {
	id := pending.ID
	if len(hosts) == 0 {
		if _, err := tx.Exec(ctx, `UPDATE allowlist SET status = $2, action = $3 WHERE id = $1`,
			id, string(decision), string(action)); err != nil {
			return nil, fmt.Errorf("decide allowlist entry %s: %w", id, err)
		}
		pending.Status, pending.Action = decision, action
		return []*event.AllowlistEntry{pending}, nil
	}

	decided := make([]*event.AllowlistEntry, 0, len(hosts))
	taken := make(map[string]bool, len(hosts))
	for _, hostID := range hosts {
		if taken[hostID] {
			continue
		}
		taken[hostID] = true
		entry := &event.AllowlistEntry{
			ID:          uuid.New().String(),
			CreatedAt:   time.Now().UTC(),
			CreatedBy:   LearningCreator,
			Description: pending.Description,
			EventTypes:  pending.EventTypes,
			HostID:      hostID,
			Action:      action,
			Enabled:     true,
			Status:      decision,
		}
		if l := pending.Learned; l != nil {
			copied := *l
			copied.Hosts = []string{hostID}
			entry.Learned = &copied
		}
		if err := insertAllowlistEntry(ctx, tx, entry); err != nil {
			return nil, err
		}
		decided = append(decided, entry)
	}

	var rest []string
	if pending.Learned != nil {
		for _, h := range pending.Learned.Hosts {
			if !taken[h] {
				rest = append(rest, h)
			}
		}
	}
	var err error
	if len(rest) == 0 {
		_, err = tx.Exec(ctx, `DELETE FROM allowlist WHERE id = $1`, id)
	} else {
		_, err = tx.Exec(ctx, `UPDATE allowlist SET seen_hosts = $2 WHERE id = $1`, id, rest)
	}
	if err != nil {
		return nil, fmt.Errorf("update PENDING entry %s: %w", id, err)
	}
	return decided, nil
}

// scanAllowlistEntry reads a single allowlist row, selected with
// allowlistColumns, from the current row cursor.
func scanAllowlistEntry(rows pgx.Rows) (*event.AllowlistEntry, error) {
	var entry event.AllowlistEntry
	var action, status string
	var eventTypesJSON, uidRangeJSON, allowedRpathsJSON, learnedKeyJSON []byte
	var learnedExePath, firstEventID string
	var occurrences int64
	var firstSeen, lastSeen *time.Time
	var hosts []string

	err := rows.Scan(
		&entry.ID, &entry.CreatedAt, &entry.CreatedBy, &entry.Description,
		&eventTypesJSON, &entry.ExeHash, &entry.ExePath,
		&entry.LibraryHash, &entry.LibraryPath,
		&entry.ProgName, &entry.ProgType, &entry.ProgHash, &entry.HostPattern,
		&uidRangeJSON, &entry.ContainerImage,
		&allowedRpathsJSON, &entry.HostID,
		&action, &entry.Expires, &entry.Enabled, &status,
		&learnedKeyJSON, &learnedExePath, &occurrences, &firstSeen, &lastSeen, &hosts,
		&firstEventID,
	)
	if err != nil {
		return nil, err
	}

	entry.Action = event.PolicyAction(action)
	entry.Status = event.EntryStatus(status)

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
	if len(allowedRpathsJSON) > 0 {
		if err := json.Unmarshal(allowedRpathsJSON, &entry.AllowedRpaths); err != nil {
			return nil, fmt.Errorf("unmarshal allowed_rpaths: %w", err)
		}
	}
	if len(learnedKeyJSON) > 0 {
		l := &event.Learned{ExePath: learnedExePath, Occurrences: occurrences, Hosts: hosts, FirstEventID: firstEventID}
		if err := json.Unmarshal(learnedKeyJSON, &l.Key); err != nil {
			return nil, fmt.Errorf("unmarshal learned_key: %w", err)
		}
		if firstSeen != nil {
			l.FirstSeen = *firstSeen
		}
		if lastSeen != nil {
			l.LastSeen = *lastSeen
		}
		if l.Hosts == nil {
			l.Hosts = []string{}
		}
		entry.Learned = l
	}
	return &entry, nil
}

// ---------------------------------------------------------------------------
// Learning mode
// ---------------------------------------------------------------------------

// SetLearningWindow starts learning mode for the fleet (w.HostID empty) or
// for one host, until w.EndsAt. It replaces any window for the same scope.
func (s *Store) SetLearningWindow(ctx context.Context, w event.LearningWindow) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO learning_mode (host_id, started_at, ends_at, started_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (host_id) DO UPDATE SET
			started_at = EXCLUDED.started_at,
			ends_at    = EXCLUDED.ends_at,
			started_by = EXCLUDED.started_by`,
		w.HostID, w.StartedAt, w.EndsAt, w.StartedBy)
	if err != nil {
		return fmt.Errorf("set learning window: %w", err)
	}
	return nil
}

// DeleteLearningWindow ends learning mode for the fleet (hostID empty) or
// one host. It returns ErrNotFound (wrapped) if there was no window.
func (s *Store) DeleteLearningWindow(ctx context.Context, hostID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM learning_mode WHERE host_id = $1`, hostID)
	if err != nil {
		return fmt.Errorf("delete learning window: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("learning window %q: %w", hostID, ErrNotFound)
	}
	return nil
}

// GetLearningWindows returns every learning window, ended or not, the fleet
// window first.
func (s *Store) GetLearningWindows(ctx context.Context) ([]event.LearningWindow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host_id, started_at, ends_at, started_by
		FROM learning_mode ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("query learning windows: %w", err)
	}
	defer rows.Close()
	var out []event.LearningWindow
	for rows.Next() {
		var w event.LearningWindow
		if err := rows.Scan(&w.HostID, &w.StartedAt, &w.EndsAt, &w.StartedBy); err != nil {
			return nil, fmt.Errorf("scan learning window: %w", err)
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate learning windows: %w", err)
	}
	return out, nil
}
