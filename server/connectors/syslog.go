package connectors

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// SyslogConnector sends events to a syslog receiver formatted as CEF
// (ArcSight Common Event Format) messages over TCP or UDP.
type SyslogConnector struct {
	conn     net.Conn
	address  string
	protocol string // "tcp" or "udp"
	logger   *zap.Logger
	mu       sync.Mutex
}

// NewSyslogConnector creates a connector that sends CEF-formatted events to
// the syslog receiver at the given address using the specified protocol.
func NewSyslogConnector(address, protocol string, logger *zap.Logger) (*SyslogConnector, error) {
	proto := strings.ToLower(protocol)
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("unsupported syslog protocol %q: must be tcp or udp", protocol)
	}

	conn, err := net.Dial(proto, address)
	if err != nil {
		return nil, fmt.Errorf("dial syslog %s://%s: %w", proto, address, err)
	}

	logger.Info("syslog connector established",
		zap.String("address", address),
		zap.String("protocol", proto),
	)

	return &SyslogConnector{
		conn:     conn,
		address:  address,
		protocol: proto,
		logger:   logger,
	}, nil
}

// Name returns the connector identifier.
func (s *SyslogConnector) Name() string { return "syslog" }

// Send formats the event as a CEF message and writes it to the syslog connection.
func (s *SyslogConnector) Send(evt *event.HookEvent) error {
	msg := formatCEF(evt)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Syslog messages are newline-delimited over TCP; UDP sends per-datagram.
	_, err := fmt.Fprintf(s.conn, "%s\n", msg)
	if err != nil {
		s.logger.Error("syslog send failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("syslog send: %w", err)
	}
	return nil
}

// Close shuts down the syslog connection.
func (s *SyslogConnector) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// severityToNum maps HookMon severity levels to CEF numeric severity.
// CEF severity ranges from 0 (lowest) to 10 (highest).
func severityToNum(sev event.Severity) int {
	switch sev {
	case event.SeverityInfo:
		return 1
	case event.SeverityWarn:
		return 4
	case event.SeverityAlert:
		return 7
	case event.SeverityCritical:
		return 10
	default:
		return 0
	}
}

// eventDescription returns a human-readable description for the event type.
func eventDescription(et event.EventType) string {
	switch et {
	case event.EventBPFLoad:
		return "BPF Program Loaded"
	case event.EventBPFAttach:
		return "BPF Program Attached"
	case event.EventExecInjection:
		return "Exec Injection Detected"
	case event.EventSHMCreate:
		return "Suspicious Shared Memory Created"
	case event.EventDlopen:
		return "Dynamic Library Loaded via dlopen"
	case event.EventLinkerConfig:
		return "Linker Configuration Modified"
	case event.EventPtraceInject:
		return "Ptrace Code Injection Detected"
	case event.EventLibIntegrity:
		return "Shared Library Modified on Disk"
	case event.EventElfRpath:
		return "Suspicious ELF RPATH/RUNPATH Detected"
	default:
		return "Unknown Hook Event"
	}
}

// formatCEF produces an ArcSight Common Event Format string for the event.
//
// Format:
//
//	CEF:0|HookMon|HookMon|1.0|<event_type>|<description>|<severity>|<extensions>
func formatCEF(evt *event.HookEvent) string {
	sevNum := severityToNum(evt.Severity)
	desc := eventDescription(evt.EventType)

	// Build extension key-value pairs.
	var ext []string

	// Source host context.
	if evt.Hostname != "" {
		ext = append(ext, fmt.Sprintf("shost=%s", cefEscape(evt.Hostname)))
	}
	ext = append(ext, fmt.Sprintf("suid=%d", evt.UID))
	if evt.ExePath != "" {
		ext = append(ext, fmt.Sprintf("sproc=%s", cefEscape(evt.ExePath)))
	}

	// BPF-specific extensions (cs1, cs2).
	if evt.BPFDetail != nil {
		ext = append(ext,
			fmt.Sprintf("cs1Label=ProgType"),
			fmt.Sprintf("cs1=%d", evt.BPFDetail.ProgType),
			fmt.Sprintf("cs2Label=ProgName"),
			fmt.Sprintf("cs2=%s", cefEscape(evt.BPFDetail.ProgName)),
		)
	}

	// Exec injection-specific extensions.
	if evt.ExecInjectionDetail != nil {
		ext = append(ext,
			fmt.Sprintf("cs1Label=LibraryPath"),
			fmt.Sprintf("cs1=%s", cefEscape(evt.ExecInjectionDetail.LibraryPath)),
			fmt.Sprintf("cs2Label=SetBy"),
			fmt.Sprintf("cs2=%s", cefEscape(evt.ExecInjectionDetail.SetBy)),
		)
	}

	// Executable hash (cs3).
	if evt.ExeHash != "" {
		ext = append(ext,
			fmt.Sprintf("cs3Label=ExeHash"),
			fmt.Sprintf("cs3=%s", cefEscape(evt.ExeHash)),
		)
	}

	// Policy result (cs4).
	if evt.PolicyResult != nil {
		ext = append(ext,
			fmt.Sprintf("cs4Label=PolicyResult"),
			fmt.Sprintf("cs4=%s", cefEscape(string(evt.PolicyResult.Action))),
		)
	}

	// ELF RPATH-specific extensions.
	if evt.ElfRpathDetail != nil {
		ext = append(ext,
			fmt.Sprintf("cs5Label=HighestRisk"),
			fmt.Sprintf("cs5=%s", cefEscape(string(evt.ElfRpathDetail.HighestRisk))),
		)
		if evt.ElfRpathDetail.RpathRaw != "" {
			ext = append(ext,
				fmt.Sprintf("cs6Label=RpathRaw"),
				fmt.Sprintf("cs6=%s", cefEscape(evt.ElfRpathDetail.RpathRaw)),
			)
		}
		if evt.ElfRpathDetail.RunpathRaw != "" {
			ext = append(ext,
				fmt.Sprintf("cs7Label=RunpathRaw"),
				fmt.Sprintf("cs7=%s", cefEscape(evt.ElfRpathDetail.RunpathRaw)),
			)
		}
	}

	// BPF instruction count.
	if evt.BPFDetail != nil && evt.BPFDetail.InsnCount > 0 {
		ext = append(ext,
			fmt.Sprintf("cn1Label=InsnCount"),
			fmt.Sprintf("cn1=%d", evt.BPFDetail.InsnCount),
		)
	}

	extensions := strings.Join(ext, " ")

	return fmt.Sprintf("CEF:0|HookMon|HookMon|1.0|%s|%s|%d|%s",
		cefEscape(string(evt.EventType)),
		cefEscape(desc),
		sevNum,
		extensions,
	)
}

// cefEscape escapes characters that are special in CEF values.
// CEF requires escaping backslashes, pipes in headers, and equals/newlines in extensions.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
