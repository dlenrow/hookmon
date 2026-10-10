package connectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dlenrow/hookmon/pkg/event"
)

// siemRFC5424 matches the syslog header the connector writes:
// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
var siemRFC5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z) ([!-~]{1,255}) hookmon - ([!-~]{1,32}) - (CEF:0\|.*)$`)

func TestFormatRFC5424_Header(t *testing.T) {
	evt := siemProcEvent(event.EventBPFLoad)
	evt.Severity = event.SeverityCritical
	evt.BPFDetail = &event.BPFDetail{ProgName: "hello_count"}
	msg := formatRFC5424(evt, syslogFacilities["local0"], "server-1", time.Now())

	m := siemRFC5424.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("not an RFC 5424 message: %q", msg)
	}
	// local0 (16) * 8 + critical (2)
	if m[1] != "130" {
		t.Errorf("PRI = %s, want 130", m[1])
	}
	if m[2] != "2026-10-10T12:00:00.123456Z" {
		t.Errorf("TIMESTAMP = %s", m[2])
	}
	if m[3] != "web-01" {
		t.Errorf("HOSTNAME = %s, want the monitored host", m[3])
	}
	if m[4] != "BPF_LOAD" {
		t.Errorf("MSGID = %s", m[4])
	}
	if !strings.HasPrefix(m[5], "CEF:0|HookMon|HookMon|1.0|BPF_LOAD|BPF Program Loaded|10|") {
		t.Errorf("MSG = %s", m[5])
	}

	// Severity mapping and facility.
	for sev, want := range map[event.Severity]int{
		event.SeverityCritical: 20*8 + 2, event.SeverityAlert: 20*8 + 3,
		event.SeverityWarn: 20*8 + 4, event.SeverityInfo: 20*8 + 6,
	} {
		e := &event.HookEvent{EventType: event.EventDlopen, Severity: sev, Hostname: "h"}
		if got := formatRFC5424(e, syslogFacilities["local4"], "s", time.Now()); !strings.HasPrefix(got, fmt.Sprintf("<%d>1 ", want)) {
			t.Errorf("%s: %q, want PRI %d", sev, got, want)
		}
	}

	// No hostname and no timestamp: the server's name and the send time.
	now := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.FixedZone("x", 3600))
	off := &event.HookEvent{EventType: event.EventAgentOffline, Severity: event.SeverityCritical}
	got := formatRFC5424(off, 16, "hookmon-appliance", now)
	if m := siemRFC5424.FindStringSubmatch(got); m == nil || m[3] != "hookmon-appliance" || m[2] != "2026-01-02T02:04:05.000006Z" || m[4] != "AGENT_OFFLINE" {
		t.Errorf("fallbacks: %q", got)
	}

	// A hostname with spaces or non-ASCII stays one header field.
	odd := &event.HookEvent{EventType: event.EventDlopen, Severity: event.SeverityWarn, Hostname: "bad hosté"}
	if m := siemRFC5424.FindStringSubmatch(formatRFC5424(odd, 16, "s", now)); m == nil || m[3] != "bad_host_" {
		t.Errorf("odd hostname: %v", m)
	}
}

// siemSyslogListener accepts TCP syslog connections and returns each
// received chunk of bytes on the channel, per connection.
type siemSyslogListener struct {
	ln    net.Listener
	conns chan net.Conn
}

func siemListenTCP(t *testing.T) *siemSyslogListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &siemSyslogListener{ln: ln, conns: make(chan net.Conn, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.conns <- c
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return l
}

func (l *siemSyslogListener) accept(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-l.conns:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog connection")
		return nil
	}
}

// siemReadOctetCounted reads one RFC 6587 octet-counted frame.
func siemReadOctetCounted(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	lenStr, err := r.ReadString(' ')
	if err != nil {
		t.Fatalf("read frame length: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
	if err != nil || n <= 0 {
		t.Fatalf("bad frame length %q", lenStr)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return string(buf)
}

func siemSyslog(t *testing.T, cfg SyslogConfig) *SyslogConnector {
	t.Helper()
	c, err := NewSyslogConnector(cfg, zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func siemCanary(id string) *event.HookEvent {
	e := siemProcEvent(event.EventBPFLoad)
	e.ID = id
	e.Severity = event.SeverityCritical
	e.BPFDetail = &event.BPFDetail{ProgName: "hello_count", ProgHash: "a04f5eef06a7f555"}
	return e
}

// TestSyslog_TCPOctetCounting: the default TCP framing is "<len> <msg>",
// with len the message's length in bytes, so a receiver can split frames
// without relying on newlines.
func TestSyslog_TCPOctetCounting(t *testing.T) {
	l := siemListenTCP(t)
	c := siemSyslog(t, SyslogConfig{Address: l.ln.Addr().String()})
	conn := l.accept(t)

	evts := []*event.HookEvent{siemCanary("e1"), siemCanary("e2")}
	evts[1].ExePath = "/usr/bin/with\nnewline" // escaped, but the frame length must still hold
	if err := c.Send(context.Background(), evts); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	for _, id := range []string{"e1", "e2"} {
		msg := siemReadOctetCounted(t, r)
		if siemRFC5424.FindStringSubmatch(msg) == nil {
			t.Errorf("frame is not RFC 5424: %q", msg)
		}
		if !strings.Contains(msg, "externalId="+id) {
			t.Errorf("frame %q lacks event %s", msg, id)
		}
	}
}

func TestSyslog_TCPLineFraming(t *testing.T) {
	l := siemListenTCP(t)
	c := siemSyslog(t, SyslogConfig{Address: l.ln.Addr().String(), Protocol: "tcp", Framing: "lf"})
	conn := l.accept(t)
	if err := c.Send(context.Background(), []*event.HookEvent{siemCanary("e1")}); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if siemRFC5424.FindStringSubmatch(strings.TrimSuffix(line, "\n")) == nil {
		t.Errorf("not an RFC 5424 line: %q", line)
	}
}

func TestSyslog_UDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c := siemSyslog(t, SyslogConfig{Address: pc.LocalAddr().String(), Protocol: "udp"})
	if err := c.Send(context.Background(), []*event.HookEvent{siemCanary("u1")}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if msg := string(buf[:n]); siemRFC5424.FindStringSubmatch(msg) == nil || !strings.Contains(msg, "externalId=u1") {
		t.Errorf("datagram is not one bare RFC 5424 message: %q", msg)
	}
}

// TestSyslog_Reconnects: after the receiver drops the connection (a
// restart), the next event goes out on a new connection and is not lost.
// The old connector kept writing to the dead socket forever.
func TestSyslog_Reconnects(t *testing.T) {
	l := siemListenTCP(t)
	c := siemSyslog(t, SyslogConfig{Address: l.ln.Addr().String()})
	first := l.accept(t)
	if err := c.Send(context.Background(), []*event.HookEvent{siemCanary("before")}); err != nil {
		t.Fatal(err)
	}
	if msg := siemReadOctetCounted(t, bufio.NewReader(first)); !strings.Contains(msg, "externalId=before") {
		t.Fatalf("first message: %q", msg)
	}
	first.Close()
	time.Sleep(50 * time.Millisecond) // let the FIN arrive

	if err := c.Send(context.Background(), []*event.HookEvent{siemCanary("after")}); err != nil {
		t.Fatalf("send after the receiver closed: %v", err)
	}
	second := l.accept(t)
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if msg := siemReadOctetCounted(t, bufio.NewReader(second)); !strings.Contains(msg, "externalId=after") {
		t.Errorf("message after reconnect: %q", msg)
	}
}

// TestSyslog_ReceiverDownIsRetryable: with the receiver gone, Send fails
// with a retryable error (the worker retries) instead of hanging.
func TestSyslog_ReceiverDownIsRetryable(t *testing.T) {
	l := siemListenTCP(t)
	c := siemSyslog(t, SyslogConfig{Address: l.ln.Addr().String()})
	l.accept(t).Close()
	l.ln.Close()
	time.Sleep(50 * time.Millisecond)
	err := c.Send(context.Background(), []*event.HookEvent{siemCanary("x")})
	if err == nil || !isRetryable(err) {
		t.Errorf("Send with the receiver down: %v, want a retryable error", err)
	}
}

// TestSyslog_DialFailureFailsInit: an unreachable receiver is an error at
// startup. The old server discarded this error and ran without syslog.
func TestSyslog_DialFailureFailsInit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := NewSyslogConnector(SyslogConfig{Address: addr}, zap.NewNop()); err == nil {
		t.Fatal("NewSyslogConnector to a closed port succeeded")
	}
}
