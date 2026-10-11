package connectors

import (
	"testing"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// TestDispatcher_HostStatusReachesEveryConnector: AGENT_OFFLINE (CRITICAL)
// and AGENT_RECOVERED (INFO) from the server go to every connector, alert
// connectors included, so a SOC that was sent the outage is also sent its
// end. Repeats are not dropped. The same INFO event through Send reaches
// only the event-feed connector.
func TestDispatcher_HostStatusReachesEveryConnector(t *testing.T) {
	alerts, crit, feed := &siemFake{name: "alert"}, &siemFake{name: "crit"}, &siemFake{name: "feed"}
	d := newDispatcher(&siemSeen{}, zap.NewNop())
	d.add(alerts, Delivery{}.withDefaults(1), defaultRetry)
	d.add(crit, Delivery{MinSeverity: event.SeverityCritical}.withDefaults(1), defaultRetry)
	d.add(feed, Delivery{MinSeverity: event.SeverityInfo}.withDefaults(1), defaultRetry)
	d.start()

	status := func(id string, et event.EventType, sev event.Severity) *event.HookEvent {
		return &event.HookEvent{ID: id, HostID: "h", EventType: et, Severity: sev,
			PolicyResult: &event.PolicyResult{Action: event.ActionAlert}}
	}
	d.Dispatch(status("off-1", event.EventAgentOffline, event.SeverityCritical))
	d.Dispatch(status("rec-1", event.EventAgentRecovered, event.SeverityInfo))
	d.Dispatch(status("off-2", event.EventAgentOffline, event.SeverityCritical))
	d.Dispatch(status("rec-2", event.EventAgentRecovered, event.SeverityInfo))
	d.Send(siemEvt("info-via-send", event.SeverityInfo, event.ActionAlert))
	d.Dispatch(nil)
	siemClose(t, d)

	statusIDs := []string{"off-1", "rec-1", "off-2", "rec-2"}
	for _, tc := range []struct {
		f    *siemFake
		want []string
	}{
		{alerts, statusIDs},
		{crit, statusIDs},
		{feed, append(append([]string{}, statusIDs...), "info-via-send")},
	} {
		if got := tc.f.ids(); !siemEqual(got, tc.want) {
			t.Errorf("%s got %v, want %v", tc.f.name, got, tc.want)
		}
	}

	// After Close, Dispatch is a no-op rather than a send on a closed queue.
	d.Dispatch(status("late", event.EventAgentRecovered, event.SeverityInfo))
}
