package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/allowlist"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Source is where the engine reads its policy: the allowlist entries that
// can match (APPROVED and REJECTED; PENDING entries never match), and the
// learning windows.
type Source interface {
	GetDecidedAllowlist(ctx context.Context) ([]*event.AllowlistEntry, error)
	GetLearningWindows(ctx context.Context) ([]event.LearningWindow, error)
}

// CandidateSink records new hooks: an unmatched event's key, as the
// PENDING allowlist entry for it. The first event of a key creates the
// entry (and is recorded as its first event); each later one adds to its
// count, last-seen time and hosts.
type CandidateSink interface {
	RecordCandidate(ctx context.Context, key event.LearnedKey, exePath, description, hostID, eventID string, seen time.Time) (event.CandidateSighting, error)
}

// candidateTimeout bounds one RecordCandidate call, so a slow database
// cannot hold up ingestion indefinitely.
const candidateTimeout = 5 * time.Second

// Engine evaluates hook events against the loaded allowlist and built-in
// rules, producing a PolicyResult for every event. It records every
// unmatched event's key as a PENDING entry, and gives each event its
// disposition: a first sighting of a key, a repeat of one still waiting for
// a decision, allowed, or denied. While learning mode (a quiet period) is
// on for the event's host, first sightings are marked quiet: stored and
// shown, but not sent to alert connectors.
type Engine struct {
	mu       sync.RWMutex
	set      *allowlist.Set
	learning map[string]time.Time // host ID ("" for the fleet) -> end of learning

	// reloadMu serializes Reload, so an older read never replaces a newer one.
	reloadMu sync.Mutex
	source   Source
	sink     CandidateSink

	now    func() time.Time
	logger *zap.Logger
}

// NewEngine creates a policy evaluation engine with an empty allowlist and
// learning mode off.
func NewEngine(logger *zap.Logger) *Engine {
	return &Engine{
		set:      allowlist.NewSet(nil),
		learning: map[string]time.Time{},
		now:      time.Now,
		logger:   logger,
	}
}

// SetSource sets where Reload reads the policy from.
func (e *Engine) SetSource(src Source) { e.source = src }

// SetCandidateSink sets where new hooks are recorded. Without a sink
// nothing is recorded, and every unmatched event is a first sighting.
func (e *Engine) SetCandidateSink(sink CandidateSink) { e.sink = sink }

// LoadAllowlist replaces the current allowlist with the provided entries.
// PENDING and disabled entries are kept out, since they never match.
func (e *Engine) LoadAllowlist(entries []*event.AllowlistEntry) {
	set := allowlist.NewSet(entries)
	e.mu.Lock()
	e.set = set
	e.mu.Unlock()
	e.logger.Info("allowlist loaded", zap.Int("entries", len(entries)), zap.Int("in_force", set.Len()))
}

// LoadLearning replaces the learning windows.
func (e *Engine) LoadLearning(windows []event.LearningWindow) {
	m := make(map[string]time.Time, len(windows))
	for _, w := range windows {
		if end, ok := m[w.HostID]; !ok || w.EndsAt.After(end) {
			m[w.HostID] = w.EndsAt
		}
	}
	e.mu.Lock()
	e.learning = m
	e.mu.Unlock()
}

// Reload reads the allowlist and the learning windows from the source and
// replaces both. The server calls it after every policy write through the
// API and on SIGHUP. Evaluations that start after Reload returns use the
// new policy.
func (e *Engine) Reload(ctx context.Context) error {
	if e.source == nil {
		return fmt.Errorf("policy engine has no source to reload from")
	}
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	entries, err := e.source.GetDecidedAllowlist(ctx)
	if err != nil {
		return fmt.Errorf("read allowlist: %w", err)
	}
	windows, err := e.source.GetLearningWindows(ctx)
	if err != nil {
		return fmt.Errorf("read learning windows: %w", err)
	}
	e.LoadAllowlist(entries)
	e.LoadLearning(windows)
	return nil
}

// Learning reports whether learning mode is on for hostID now: a fleet
// window or a window for that host has not ended.
func (e *Engine) Learning(hostID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.learningLocked(hostID, e.now())
}

func (e *Engine) learningLocked(hostID string, now time.Time) bool {
	if end, ok := e.learning[""]; ok && now.Before(end) {
		return true
	}
	if hostID == "" {
		return false
	}
	end, ok := e.learning[hostID]
	return ok && now.Before(end)
}

// Evaluate runs the event through the allowlist and built-in rules, returning
// a PolicyResult and setting the event's Severity accordingly. The event's
// Severity on entry is the one the bus set; see classifySeverity. The
// result's Disposition says whether the server keeps the event.
func (e *Engine) Evaluate(evt *event.HookEvent) *event.PolicyResult {
	// Agent lifecycle events always produce an ALERT.
	if evt.EventType == event.EventAgentOffline || evt.EventType == event.EventAgentRecovered {
		result := &event.PolicyResult{
			Action:      event.ActionAlert,
			Reason:      fmt.Sprintf("agent lifecycle event: %s", evt.EventType),
			Disposition: event.DispositionLifecycle,
		}
		evt.Severity = event.SeverityAlert
		evt.PolicyResult = result
		return result
	}

	now := e.now()
	e.mu.RLock()
	set := e.set
	learning := e.learningLocked(evt.HostID, now)
	e.mu.RUnlock()

	// BPF inventory events are a census the sensor bus repeats every few
	// minutes, not an action by a process. A loaded program on the allowlist
	// is dropped, and so is the host summary. A program that is not on it is
	// a new hook like any other, at ALERT: a program nobody approved,
	// whenever it was loaded, is what the inventory is for. A denied program
	// alerts on every scan.
	if evt.EventType == event.EventBPFInventory {
		result, matched := inventoryResult(set, evt, now)
		evt.Severity = event.SeverityAlert
		switch {
		case !matched:
			e.sight(evt, result, learning)
		case result.Action == event.ActionAllow:
			result.Disposition = event.DispositionAllowed
		default:
			result.Disposition = event.DispositionDenied
		}
		if result.Disposition == event.DispositionAllowed {
			evt.Severity = event.SeverityInfo
		}
		evt.PolicyResult = result
		return result
	}

	// Built-in rules name what looks wrong with an unmatched event. A
	// matching allowlist entry decides the event instead.
	ruleResult := evaluateRules(evt)

	if entry := set.Match(evt, now); entry != nil {
		result := &event.PolicyResult{
			Action:         entry.Action,
			MatchedEntryID: entry.ID,
			Reason:         fmt.Sprintf("matched allowlist entry: %s", entry.Description),
			Disposition:    event.DispositionDenied,
		}
		if entry.Action == event.ActionAllow {
			result.Disposition = event.DispositionAllowed
		}
		evt.PolicyResult = result
		evt.Severity = classifySeverity(result, evt)
		e.logger.Debug("event matched allowlist",
			zap.String("event_id", evt.ID),
			zap.String("entry_id", entry.ID),
			zap.String("action", string(entry.Action)),
		)
		return result
	}

	// No allowlist match. Use the built-in rule result if one fired,
	// otherwise generate a default ALERT.
	result := ruleResult
	if result == nil {
		result = &event.PolicyResult{
			Action: event.ActionAlert,
			Reason: fmt.Sprintf("no allowlist match for %s event from %s (exe=%s, hash=%s)",
				evt.EventType, evt.Hostname, evt.ExePath, evt.ExeHash),
		}
	}
	evt.Severity = classifySeverity(result, evt)
	e.sight(evt, result, learning)
	if result.Disposition == event.DispositionAllowed {
		evt.Severity = event.SeverityInfo
	}
	evt.PolicyResult = result
	if result.Disposition == event.DispositionFirstSighting {
		e.logger.Info("new hook: first sighting",
			zap.String("event_id", evt.ID),
			zap.String("event_type", string(evt.EventType)),
			zap.String("hostname", evt.Hostname),
			zap.String("candidate_id", result.CandidateID),
			zap.String("reason", result.Reason),
		)
	}
	return result
}

// sight records an unmatched event's key as a new hook and sets the
// result's disposition from what the store found:
//   - the event created the PENDING entry: a first sighting, quiet during a
//     learning window;
//   - a PENDING entry already existed: a repeat;
//   - a decided entry is already in force (the engine has not reloaded it
//     yet): allowed or denied, as that entry says.
//
// Without a sink, or when the store fails, the event is a first sighting:
// HookMon keeps what it cannot place rather than drop it.
func (e *Engine) sight(evt *event.HookEvent, result *event.PolicyResult, learning bool) {
	firstSighting := func() {
		result.Disposition = event.DispositionFirstSighting
		result.Quiet = learning
	}
	if e.sink == nil {
		firstSighting()
		return
	}
	key := allowlist.KeyOf(evt)
	ctx, cancel := context.WithTimeout(context.Background(), candidateTimeout)
	defer cancel()
	seen := evt.Timestamp
	if seen.IsZero() {
		seen = e.now()
	}
	s, err := e.sink.RecordCandidate(ctx, key, evt.ExePath, allowlist.Describe(key, evt.ExePath), evt.HostID, evt.ID, seen)
	if err != nil {
		e.logger.Warn("recording a new hook failed; keeping the event as a first sighting",
			zap.String("event_id", evt.ID), zap.Error(err))
		firstSighting()
		return
	}
	switch {
	case s.ID == "" && s.DecidedAction == event.ActionAllow:
		result.Action = event.ActionAllow
		result.Disposition = event.DispositionAllowed
		result.Reason += "; allowed by an entry decided since the policy was loaded"
	case s.ID == "":
		result.Disposition = event.DispositionDenied
		result.Reason += "; denied by an entry decided since the policy was loaded"
	case s.Created:
		firstSighting()
		result.CandidateID = s.ID
		result.Reason += fmt.Sprintf("; first sighting: PENDING entry %s", s.ID)
	default:
		result.Disposition = event.DispositionRepeat
		result.CandidateID = s.ID
		result.Reason += fmt.Sprintf("; repeat of PENDING entry %s", s.ID)
	}
}

// inventoryResult evaluates a BPF_INVENTORY event against the allowlist,
// and reports whether an entry decided it. Built-in rules do not apply: an
// inventory event has no process context.
func inventoryResult(set *allowlist.Set, evt *event.HookEvent, now time.Time) (*event.PolicyResult, bool) {
	if evt.BPFInventoryDetail != nil && evt.BPFInventoryDetail.Summary {
		return &event.PolicyResult{
			Action: event.ActionAllow,
			Reason: fmt.Sprintf("BPF inventory summary: %d programs loaded on %s",
				evt.BPFInventoryDetail.ProgCount, evt.Hostname),
		}, true
	}

	if entry := set.Match(evt, now); entry != nil {
		return &event.PolicyResult{
			Action:         entry.Action,
			MatchedEntryID: entry.ID,
			Reason:         fmt.Sprintf("matched allowlist entry: %s", entry.Description),
		}, true
	}

	var name, tag string
	var id uint32
	if evt.BPFDetail != nil {
		name, tag, id = evt.BPFDetail.ProgName, evt.BPFDetail.ProgHash, evt.BPFDetail.ProgID
	}
	return &event.PolicyResult{
		Action: event.ActionAlert,
		Reason: fmt.Sprintf("BPF inventory: loaded program %q (id=%d, tag=%s) on %s has no allowlist match",
			name, id, tag, evt.Hostname),
	}, false
}
