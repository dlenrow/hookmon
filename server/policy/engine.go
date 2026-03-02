package policy

import (
	"fmt"
	"sync"

	"github.com/dlenrow/hookmon/pkg/event"
	"go.uber.org/zap"
)

// Engine evaluates hook events against the loaded allowlist and built-in
// rules, producing a PolicyResult for every event.
type Engine struct {
	allowlist []*event.AllowlistEntry
	mu        sync.RWMutex
	logger    *zap.Logger
}

// NewEngine creates a policy evaluation engine.
func NewEngine(logger *zap.Logger) *Engine {
	return &Engine{
		logger: logger,
	}
}

// LoadAllowlist replaces the current allowlist with the provided entries.
func (e *Engine) LoadAllowlist(entries []*event.AllowlistEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowlist = entries
	e.logger.Info("allowlist loaded", zap.Int("entries", len(entries)))
}

// Evaluate runs the event through the allowlist and built-in rules, returning
// a PolicyResult and setting the event's Severity accordingly.
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

	// Check built-in rules first. If a rule fires, it may elevate severity
	// but we still check the allowlist — a matching allowlist entry can
	// override the rule.
	ruleResult := evaluateRules(evt)

	// Evaluate against the allowlist.
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, entry := range e.allowlist {
		if Matches(entry, evt) {
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
	}

	// No allowlist match. Use the built-in rule result if one fired,
	// otherwise generate a default ALERT.
	if ruleResult != nil {
		evt.PolicyResult = ruleResult
		evt.Severity = classifySeverity(ruleResult, evt)
		e.logger.Warn("event matched built-in rule",
			zap.String("event_id", evt.ID),
			zap.String("reason", ruleResult.Reason),
		)
		return ruleResult
	}

	result := &event.PolicyResult{
		Action: event.ActionAlert,
		Reason: fmt.Sprintf("no allowlist match for %s event from %s (exe=%s, hash=%s)",
			evt.EventType, evt.Hostname, evt.ExePath, evt.ExeHash),
	}
	evt.PolicyResult = result
	evt.Severity = classifySeverity(result, evt)
	e.logger.Warn("event has no allowlist match",
		zap.String("event_id", evt.ID),
		zap.String("event_type", string(evt.EventType)),
		zap.String("hostname", evt.Hostname),
	)
	return result
}

// classifySeverity determines the severity based on the policy result and
// event context, following the severity classification table from the spec.
func classifySeverity(result *event.PolicyResult, evt *event.HookEvent) event.Severity {
	// If the event matched an allowlist ALLOW entry, it is informational.
	if result.Action == event.ActionAllow {
		return event.SeverityInfo
	}

	// No allowlist match (ALERT or DENY). Classify based on event context.

	// /etc/ld.so.preload modification is always CRITICAL.
	if evt.EventType == event.EventLDPreload && evt.PreloadDetail != nil {
		if evt.PreloadDetail.SetBy == "/etc/ld.so.preload" {
			return event.SeverityCritical
		}
	}

	// bpftime-pattern shared memory from non-whitelisted process is CRITICAL.
	if evt.EventType == event.EventSHMCreate && evt.SHMDetail != nil {
		if evt.SHMDetail.Pattern == "bpftime" {
			return event.SeverityCritical
		}
	}

	// Any unmatched event from root (UID 0) is CRITICAL.
	if evt.UID == 0 {
		return event.SeverityCritical
	}

	// LD_PRELOAD from non-root, non-whitelisted library is ALERT.
	if evt.EventType == event.EventLDPreload {
		return event.SeverityAlert
	}

	// No allowlist match but known event type: WARN for recognized BPF types,
	// ALERT for unknown binary hash or other events.
	if evt.ExeHash == "" {
		// Unknown binary hash is more suspicious.
		return event.SeverityAlert
	}

	return event.SeverityWarn
}
