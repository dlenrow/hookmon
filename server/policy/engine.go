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

// CandidateSink records what learning mode sees: one unmatched event, as a
// PENDING allowlist entry for its key. Repeats of the key add to the
// entry's count, last-seen time and hosts. It returns the entry's ID, or ""
// if a decided entry for the key already exists.
type CandidateSink interface {
	RecordCandidate(ctx context.Context, key event.LearnedKey, exePath, description, hostID string, seen time.Time) (string, error)
}

// candidateTimeout bounds one RecordCandidate call, so a slow database
// cannot hold up ingestion indefinitely.
const candidateTimeout = 5 * time.Second

// Engine evaluates hook events against the loaded allowlist and built-in
// rules, producing a PolicyResult for every event. While learning mode is
// on for an event's host, it records every unmatched event as a candidate.
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

// SetCandidateSink sets where learning mode records candidates. Without a
// sink, learning mode records nothing.
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
// Severity on entry is the one the bus set; see classifySeverity.
func (e *Engine) Evaluate(evt *event.HookEvent) *event.PolicyResult {
	// Agent lifecycle events always produce an ALERT.
	if evt.EventType == event.EventAgentOffline || evt.EventType == event.EventAgentRecovered {
		result := &event.PolicyResult{
			Action: event.ActionAlert,
			Reason: fmt.Sprintf("agent lifecycle event: %s", evt.EventType),
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
	// minutes, not an action by a process, so they are always INFO. The
	// allowlist is still consulted: the result records whether each loaded
	// program is known (matched entry) or not (ALERT, meaning "not on the
	// allowlist"), so unknown programs can be found by query.
	if evt.EventType == event.EventBPFInventory {
		result, matched := inventoryResult(set, evt, now)
		evt.Severity = event.SeverityInfo
		if !matched && learning {
			e.learn(evt, result)
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
	if learning {
		e.learn(evt, result)
	}
	evt.PolicyResult = result
	if ruleResult != nil {
		e.logger.Warn("event matched built-in rule",
			zap.String("event_id", evt.ID),
			zap.String("reason", ruleResult.Reason),
		)
	} else {
		e.logger.Warn("event has no allowlist match",
			zap.String("event_id", evt.ID),
			zap.String("event_type", string(evt.EventType)),
			zap.String("hostname", evt.Hostname),
		)
	}
	return result
}

// learn records an unmatched event as a learning-mode candidate and notes
// the candidate in the result's reason.
func (e *Engine) learn(evt *event.HookEvent, result *event.PolicyResult) {
	if e.sink == nil {
		return
	}
	key := allowlist.KeyOf(evt)
	ctx, cancel := context.WithTimeout(context.Background(), candidateTimeout)
	defer cancel()
	seen := evt.Timestamp
	if seen.IsZero() {
		seen = e.now()
	}
	id, err := e.sink.RecordCandidate(ctx, key, evt.ExePath, allowlist.Describe(key, evt.ExePath), evt.HostID, seen)
	if err != nil {
		e.logger.Warn("learning mode: recording candidate failed",
			zap.String("event_id", evt.ID), zap.Error(err))
		return
	}
	if id != "" {
		result.Reason += fmt.Sprintf("; learning mode: PENDING entry %s", id)
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
