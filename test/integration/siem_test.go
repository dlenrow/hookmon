package integration_test

// SIEM connectors (fix plan step 7d) through the real server: events from
// an enrolled bus over mutual TLS, the policy engine and PostgreSQL, out
// to a syslog receiver and a webhook receiver on localhost. Like the other
// tests here they need HOOKMON_TEST_PG_DSN.

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/connectors"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// siemSyslogRx is a TCP syslog receiver that reads RFC 6587 octet-counted
// frames.
type siemSyslogRx struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func siemStartSyslog(t *testing.T) *siemSyslogRx {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rx := &siemSyslogRx{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go rx.read(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return rx
}

func (rx *siemSyslogRx) read(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			rx.add("BAD FRAME LENGTH " + lenStr)
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		rx.add(string(buf))
	}
}

func (rx *siemSyslogRx) add(m string) {
	rx.mu.Lock()
	rx.msgs = append(rx.msgs, m)
	rx.mu.Unlock()
}

// matching returns the received messages containing every substring.
func (rx *siemSyslogRx) matching(subs ...string) []string {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	var out []string
next:
	for _, m := range rx.msgs {
		for _, s := range subs {
			if !strings.Contains(m, s) {
				continue next
			}
		}
		out = append(out, m)
	}
	return out
}

// siemWebhookRx records the events webhook POSTs carry.
type siemWebhookRx struct {
	*httptest.Server
	mu     sync.Mutex
	events []*event.HookEvent
	bodies []string
}

func siemStartWebhook(t *testing.T) *siemWebhookRx {
	t.Helper()
	rx := &siemWebhookRx{}
	rx.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var evt event.HookEvent
		if r.Header.Get("Authorization") != "Bearer siem-test" || json.Unmarshal(data, &evt) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rx.mu.Lock()
		rx.events = append(rx.events, &evt)
		rx.bodies = append(rx.bodies, string(data))
		rx.mu.Unlock()
	}))
	t.Cleanup(rx.Close)
	return rx
}

func (rx *siemWebhookRx) find(f func(*event.HookEvent) bool) []*event.HookEvent {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	var out []*event.HookEvent
	for _, e := range rx.events {
		if f(e) {
			out = append(out, e)
		}
	}
	return out
}

func (rx *siemWebhookRx) byID(id string) []*event.HookEvent {
	return rx.find(func(e *event.HookEvent) bool { return e.ID == id })
}

var siemRFC5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) hookmon - (\S+) - (CEF:0\|HookMon\|HookMon\|.*)$`)

func siemBPFEvent(id string) *event.HookEvent {
	e := enrEvent(id)
	e.UID = 0
	e.ExePath = "/usr/local/bin/siem-loader"
	e.ExeHash = "sha256:" + strings.Repeat("5e", 32)
	e.BPFDetail = &event.BPFDetail{BPFCommand: 5, ProgType: 2, ProgName: "hello_count", ProgHash: "a04f5eef06a7f555", InsnCount: 12}
	return e
}

// TestSIEM_AlertsReachSyslogAndWebhook: the first sighting of a BPF load
// from root (CRITICAL) reaches the syslog connector, an alert connector, as
// an RFC 5424 message with CEF. Its repeat is counted on the new hook's
// PENDING entry and reaches no connector. The webhook, an event feed
// (min_severity INFO), gets every stored event: the canary and an INFO
// first sighting.
func TestSIEM_AlertsReachSyslogAndWebhook(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	syslogRx := siemStartSyslog(t)
	hookRx := siemStartWebhook(t)

	cfg := enrServerConfig(pki, dsn, tok)
	cfg.Connectors = connectors.Config{
		Syslog: &connectors.SyslogConfig{Address: syslogRx.ln.Addr().String()},
		Webhook: &connectors.WebhookConfig{URL: hookRx.URL + "/hook", Headers: map[string]string{"Authorization": "Bearer siem-test"},
			Delivery: connectors.Delivery{MinSeverity: event.SeverityInfo}},
	}
	s := enrStartServer(t, cfg)
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)

	info := enrEvent("siem-info")
	info.EventType = event.EventSHMCreate
	info.Severity = event.SeverityInfo
	info.UID = 1000
	info.SHMDetail = &event.SHMDetail{SHMName: "chromium-xyz", Pattern: "unknown"}
	for _, e := range []*event.HookEvent{siemBPFEvent("siem-canary"), siemBPFEvent("siem-repeat"), info} {
		if err := tr.SendEvent(e); err != nil {
			t.Fatal(err)
		}
	}

	// The repeat of the canary's program is counted on its PENDING entry
	// and dropped: it reaches no connector, not even the full event feed.
	enrWaitFor(t, 15*time.Second, "the canary and the INFO event at the webhook", func() bool {
		return len(hookRx.byID("siem-canary")) == 1 && len(hookRx.byID("siem-info")) == 1
	})
	enrWaitFor(t, 15*time.Second, "the canary at the syslog receiver", func() bool {
		return len(syslogRx.matching("externalId=siem-canary")) == 1
	})
	time.Sleep(1500 * time.Millisecond) // the repeat and the INFO event would have arrived by now

	msg := syslogRx.matching("externalId=siem-canary")[0]
	t.Logf("syslog message: %s", msg)
	m := siemRFC5424.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("not RFC 5424 with CEF: %q", msg)
	}
	// PRI 130 is local0 (16) * 8 + critical (2); HOSTNAME is the hostname
	// the host enrolled with. Since step 7f the "bus" the event itself
	// carries is not used: it is self-asserted.
	enrolledName, _ := os.Hostname()
	if m[1] != "130" || m[3] != enrolledName || m[4] != "BPF_LOAD" {
		t.Errorf("header: PRI %s, HOSTNAME %s (want the enrolled %s), MSGID %s", m[1], m[3], enrolledName, m[4])
	}
	if !strings.Contains(m[5], "shost="+enrolledName+" ") {
		t.Errorf("CEF shost is not the enrolled hostname %s: %s", enrolledName, m[5])
	}
	for _, want := range []string{"|BPF_LOAD|BPF Program Loaded|10|", "cs2Label=ProgName cs2=hello_count", "cs5Label=ProgTag cs5=a04f5eef06a7f555",
		"deviceExternalId=" + bus.HostID, "cs4Label=PolicyResult cs4=ALERT", "suid=0", "sproc=/usr/local/bin/siem-loader"} {
		if !strings.Contains(m[5], want) {
			t.Errorf("CEF lacks %q: %s", want, m[5])
		}
	}
	if n := len(syslogRx.matching("externalId=siem-repeat")); n != 0 {
		t.Errorf("the repeat reached the alert connector %d times", n)
	}
	if n := len(hookRx.byID("siem-repeat")); n != 0 {
		t.Errorf("the repeat reached the event-feed connector %d times", n)
	}
	if n := len(syslogRx.matching("externalId=siem-info")); n != 0 {
		t.Errorf("the INFO event reached the alert connector")
	}

	got := hookRx.byID("siem-canary")[0]
	if got.HostID != bus.HostID || got.Severity != event.SeverityCritical || got.PolicyResult == nil ||
		got.PolicyResult.Action != event.ActionAlert || got.BPFDetail == nil || got.BPFDetail.ProgHash != "a04f5eef06a7f555" {
		t.Errorf("webhook event: %+v", got)
	}
	if i := hookRx.byID("siem-info")[0]; i.Severity != event.SeverityInfo {
		t.Errorf("webhook INFO event severity %s", i.Severity)
	}
}

// TestSIEM_OfflineAlertReachesWebhook: stopping the bus makes the
// watchdog's AGENT_OFFLINE reach the webhook (an alert connector) and the
// syslog receiver.
func TestSIEM_OfflineAlertReachesWebhook(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	syslogRx := siemStartSyslog(t)
	hookRx := siemStartWebhook(t)

	cfg := enrServerConfig(pki, dsn, tok)
	cfg.Connectors = connectors.Config{
		Syslog:  &connectors.SyslogConfig{Address: syslogRx.ln.Addr().String()},
		Webhook: &connectors.WebhookConfig{URL: hookRx.URL, Headers: map[string]string{"Authorization": "Bearer siem-test"}},
	}
	s := enrStartServer(t, cfg)
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, stopBus := enrRunBus(t, bus, nil)
	if err := tr.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	stopBus()
	stopped := time.Now()

	offline := func(e *event.HookEvent) bool {
		return e.EventType == event.EventAgentOffline && e.HostID == bus.HostID
	}
	limit := cfg.Watchdog.HeartbeatTimeout + cfg.Watchdog.CheckInterval + 5*time.Second
	enrWaitFor(t, limit, "AGENT_OFFLINE at the webhook", func() bool { return len(hookRx.find(offline)) == 1 })
	t.Logf("AGENT_OFFLINE reached the webhook %v after the bus stopped", time.Since(stopped).Round(10*time.Millisecond))
	evt := hookRx.find(offline)[0]
	if evt.Severity != event.SeverityCritical || evt.PolicyResult == nil || evt.PolicyResult.Action != event.ActionAlert {
		t.Errorf("offline event %+v", evt)
	}
	enrWaitFor(t, 5*time.Second, "AGENT_OFFLINE at the syslog receiver", func() bool {
		return len(syslogRx.matching("|AGENT_OFFLINE|Sensor Bus Offline|10|", "deviceExternalId="+bus.HostID)) == 1
	})
	msg := syslogRx.matching("|AGENT_OFFLINE|")[0]
	t.Logf("syslog message: %s", msg)
	if strings.Contains(msg, "suid=") {
		t.Errorf("offline message carries a process UID: %s", msg)
	}
}
