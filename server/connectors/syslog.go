package connectors

import (
	"context"
	"errors"
	"fmt"

	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

const (
	framingOctetCounting = "octet-counting"
	framingLF            = "lf"

	syslogDialTimeout  = 10 * time.Second
	syslogWriteTimeout = 10 * time.Second
)

var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// SyslogConnector sends each event as an RFC 5424 syslog message whose MSG
// is a CEF record (see formatCEF):
//
//	<PRI>1 TIMESTAMP HOSTNAME hookmon - MSGID - CEF:0|HookMon|...
//
// PRI is facility*8 plus the syslog severity (CRITICAL 2, ALERT 3, WARN 4,
// INFO 6). TIMESTAMP is the detection time in UTC with microseconds.
// HOSTNAME is the monitored host, where the hook was seen (the server's
// own name for an event with none). MSGID is the event type.
//
// Over TCP, messages are framed by octet counting (RFC 6587 section
// 3.4.1: "<length> <message>") or, with framing lf, end in a newline. A
// broken connection is redialled: before each write the connector checks
// whether the receiver has closed it, and a failed write is retried once
// on a new connection. Over UDP, each message is one datagram.
type SyslogConnector struct {
	network  string
	address  string
	framing  string
	facility int
	hostname string
	logger   *zap.Logger

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogConnector dials the receiver once, so an address that cannot be
// reached fails startup. Later failures redial.
func NewSyslogConnector(cfg SyslogConfig, logger *zap.Logger) (*SyslogConnector, error) {
	network := strings.ToLower(cfg.Protocol)
	if network == "" {
		network = "tcp"
	}
	framing := cfg.Framing
	if network == "tcp" && framing == "" {
		framing = framingOctetCounting
	}
	fac := "local0"
	if cfg.Facility != "" {
		fac = strings.ToLower(cfg.Facility)
	}
	facility, ok := syslogFacilities[fac]
	if !ok {
		return nil, fmt.Errorf("unknown facility %q", cfg.Facility)
	}
	host, _ := os.Hostname()
	s := &SyslogConnector{
		network:  network,
		address:  cfg.Address,
		framing:  framing,
		facility: facility,
		hostname: headerField(host, 255),
		logger:   logger,
	}
	if err := s.dial(); err != nil {
		return nil, err
	}
	logger.Info("syslog connector connected",
		zap.String("address", cfg.Address),
		zap.String("protocol", network),
		zap.String("framing", framing),
		zap.String("facility", fac),
	)
	return s, nil
}

// Name returns the connector identifier.
func (s *SyslogConnector) Name() string { return "syslog" }

// Send writes one message per event.
func (s *SyslogConnector) Send(ctx context.Context, batch []*event.HookEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, evt := range batch {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg := s.frame(formatRFC5424(evt, s.facility, s.hostname, time.Now()))
		if err := s.write(ctx, msg); err != nil {
			return fmt.Errorf("syslog event %s: %w", evt.ID, err)
		}
	}
	return nil
}

// frame applies the transport's framing.
func (s *SyslogConnector) frame(msg string) []byte {
	switch s.framing {
	case framingOctetCounting:
		return []byte(strconv.Itoa(len(msg)) + " " + msg)
	case framingLF:
		return []byte(msg + "\n")
	}
	return []byte(msg)
}

// write sends one framed message, redialling once if the connection is
// gone. Called with s.mu held.
func (s *SyslogConnector) write(ctx context.Context, msg []byte) error {
	if s.conn != nil && s.network == "tcp" && peerClosed(s.conn) {
		s.logger.Warn("syslog receiver closed the connection; reconnecting", zap.String("address", s.address))
		s.closeConn()
	}
	if s.conn == nil {
		if err := s.dial(); err != nil {
			return retryable(err)
		}
	}
	err := s.writeConn(ctx, msg)
	if err == nil {
		return nil
	}
	s.logger.Warn("syslog write failed; reconnecting", zap.String("address", s.address), zap.Error(err))
	s.closeConn()
	if err := s.dial(); err != nil {
		return retryable(err)
	}
	if err := s.writeConn(ctx, msg); err != nil {
		s.closeConn()
		return retryable(fmt.Errorf("write: %w", err))
	}
	return nil
}

func (s *SyslogConnector) writeConn(ctx context.Context, msg []byte) error {
	deadline := time.Now().Add(syslogWriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.conn.SetWriteDeadline(deadline)
	_, err := s.conn.Write(msg)
	return err
}

func (s *SyslogConnector) dial() error {
	conn, err := net.DialTimeout(s.network, s.address, syslogDialTimeout)
	if err != nil {
		return fmt.Errorf("dial syslog %s://%s: %w", s.network, s.address, err)
	}
	s.conn = conn
	return nil
}

func (s *SyslogConnector) closeConn() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// peerClosed reports whether the receiver has closed a TCP connection. A
// syslog receiver never sends, so a read that returns at once with EOF or
// an error other than a timeout means the connection is gone. Without
// this check the first message after the receiver goes away would be
// accepted by the kernel and lost.
func peerClosed(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		return false // the receiver sent something; ignore it
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true // io.EOF or a reset
}

// Close closes the connection.
func (s *SyslogConnector) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// syslogSeverity maps HookMon severity to the RFC 5424 severity.
func syslogSeverity(sev event.Severity) int {
	switch sev {
	case event.SeverityCritical:
		return 2 // critical
	case event.SeverityAlert:
		return 3 // error
	case event.SeverityWarn:
		return 4 // warning
	case event.SeverityInfo:
		return 6 // informational
	}
	return 5 // notice
}

// formatRFC5424 builds the syslog message (without transport framing).
// fallbackHost is used when the event has no hostname; now when it has no
// timestamp.
func formatRFC5424(evt *event.HookEvent, facility int, fallbackHost string, now time.Time) string {
	ts := evt.Timestamp
	if ts.IsZero() {
		ts = now
	}
	host := headerField(evt.Hostname, 255)
	if host == "-" {
		host = fallbackHost
	}
	if host == "" {
		host = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s hookmon - %s - %s",
		facility*8+syslogSeverity(evt.Severity),
		ts.UTC().Format("2006-01-02T15:04:05.000000Z"),
		host,
		headerField(string(evt.EventType), 32),
		formatCEF(evt),
	)
}

// headerField makes s a valid RFC 5424 header field: printable US-ASCII
// without spaces, at most max characters, or "-" (the NILVALUE) when empty.
func headerField(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r >= 33 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
