package transport

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dlenrow/hookmon/agent/config"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/pkg/version"
)

// GRPCTransport streams events to the hookmon-server over mTLS gRPC.
type GRPCTransport struct {
	cfg       *config.AgentConfig
	conn      *grpc.ClientConn
	client    hookmonv1.AgentServiceClient
	stream    hookmonv1.AgentService_StreamEventsClient
	logger    *zap.Logger
	fallback  *FallbackLogger
	mu        sync.Mutex
	connected bool
	eventsSent uint64
	startTime  time.Time
}

// NewGRPCTransport creates a new gRPC transport.
func NewGRPCTransport(cfg *config.AgentConfig, logger *zap.Logger) *GRPCTransport {
	return &GRPCTransport{
		cfg:       cfg,
		logger:    logger,
		fallback:  NewFallbackLogger(cfg.FallbackLogPath),
		startTime: time.Now(),
	}
}

// Connect establishes the gRPC connection and opens the event stream.
func (t *GRPCTransport) Connect(ctx context.Context) error {
	var opts []grpc.DialOption

	if t.cfg.TLS.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else if t.cfg.TLS.CertFile != "" {
		creds, err := hcrypto.LoadClientTLS(
			t.cfg.TLS.CertFile, t.cfg.TLS.KeyFile,
			t.cfg.TLS.CAFile, t.cfg.TLS.ServerName,
		)
		if err != nil {
			return fmt.Errorf("load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(t.cfg.ServerAddr, opts...)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	t.mu.Lock()
	t.conn = conn
	t.client = hookmonv1.NewAgentServiceClient(conn)
	t.mu.Unlock()

	if err := t.openStream(ctx); err != nil {
		return err
	}

	t.mu.Lock()
	t.connected = true
	t.mu.Unlock()

	t.logger.Info("connected to server", zap.String("addr", t.cfg.ServerAddr))
	return nil
}

func (t *GRPCTransport) openStream(ctx context.Context) error {
	stream, err := t.client.StreamEvents(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	t.mu.Lock()
	t.stream = stream
	t.mu.Unlock()
	return nil
}

// SendEvent sends an event to the server, falling back to local log on failure.
func (t *GRPCTransport) SendEvent(evt *event.HookEvent) error {
	t.mu.Lock()
	stream := t.stream
	connected := t.connected
	t.mu.Unlock()

	if !connected || stream == nil {
		return t.fallback.Write(evt)
	}

	msg := &hookmonv1.AgentMessage{
		Event: eventToProto(evt),
	}
	if err := stream.Send(msg); err != nil {
		t.logger.Warn("send failed, writing to fallback", zap.Error(err))
		t.mu.Lock()
		t.connected = false
		t.mu.Unlock()
		return t.fallback.Write(evt)
	}

	t.mu.Lock()
	t.eventsSent++
	t.mu.Unlock()
	return nil
}

// SendHeartbeat sends a heartbeat message to the server.
func (t *GRPCTransport) SendHeartbeat() error {
	t.mu.Lock()
	stream := t.stream
	connected := t.connected
	sent := t.eventsSent
	t.mu.Unlock()

	if !connected || stream == nil {
		return fmt.Errorf("not connected")
	}

	msg := &hookmonv1.AgentMessage{
		Heartbeat: &hookmonv1.Heartbeat{
			HostID:        t.cfg.HostID,
			Timestamp:     time.Now(),
			AgentVersion:  version.Version,
			EventsSent:    sent,
			UptimeSeconds: uint64(time.Since(t.startTime).Seconds()),
		},
	}
	return stream.Send(msg)
}

// Close shuts down the gRPC connection.
func (t *GRPCTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stream != nil {
		t.stream.CloseSend()
	}
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// IsConnected reports whether the transport has an active connection.
func (t *GRPCTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

func eventToProto(evt *event.HookEvent) *hookmonv1.HookEvent {
	pe := &hookmonv1.HookEvent{
		ID:          evt.ID,
		Timestamp:   evt.Timestamp,
		HostID:      evt.HostID,
		Hostname:    evt.Hostname,
		EventType:   eventTypeToProto(evt.EventType),
		Severity:    severityToProto(evt.Severity),
		PID:         evt.PID,
		PPID:        evt.PPID,
		UID:         evt.UID,
		GID:         evt.GID,
		Comm:        evt.Comm,
		Cmdline:     evt.Cmdline,
		ExePath:     evt.ExePath,
		ExeHash:     evt.ExeHash,
		CgroupPath:  evt.CgroupPath,
		ContainerID: evt.ContainerID,
		Namespace:   evt.Namespace,
	}

	if evt.BPFDetail != nil {
		pe.BPFDetail = &hookmonv1.BPFDetail{
			BPFCommand: evt.BPFDetail.BPFCommand,
			ProgType:   evt.BPFDetail.ProgType,
			ProgName:   evt.BPFDetail.ProgName,
			AttachType: evt.BPFDetail.AttachType,
			TargetFD:   evt.BPFDetail.TargetFD,
			InsnCount:  evt.BPFDetail.InsnCount,
			ProgHash:   evt.BPFDetail.ProgHash,
		}
	}

	if evt.ExecInjectionDetail != nil {
		pe.ExecInjectionDetail = &hookmonv1.ExecInjectionDetail{
			LibraryPath:  evt.ExecInjectionDetail.LibraryPath,
			LibraryHash:  evt.ExecInjectionDetail.LibraryHash,
			TargetBinary: evt.ExecInjectionDetail.TargetBinary,
			SetBy:        evt.ExecInjectionDetail.SetBy,
			EnvVar:       evt.ExecInjectionDetail.EnvVar,
		}
	}

	if evt.SHMDetail != nil {
		pe.SHMDetail = &hookmonv1.SHMDetail{
			SHMName: evt.SHMDetail.SHMName,
			Size:    evt.SHMDetail.Size,
			Pattern: evt.SHMDetail.Pattern,
		}
	}

	if evt.DlopenDetail != nil {
		pe.DlopenDetail = &hookmonv1.DlopenDetail{
			LibraryPath: evt.DlopenDetail.LibraryPath,
			LibraryHash: evt.DlopenDetail.LibraryHash,
			Flags:       int32(evt.DlopenDetail.Flags),
		}
	}

	if evt.LinkerConfigDetail != nil {
		pe.LinkerConfigDetail = &hookmonv1.LinkerConfigDetail{
			FilePath:  evt.LinkerConfigDetail.FilePath,
			Operation: evt.LinkerConfigDetail.Operation,
			OldHash:   evt.LinkerConfigDetail.OldHash,
			NewHash:   evt.LinkerConfigDetail.NewHash,
		}
	}

	if evt.PtraceDetail != nil {
		pe.PtraceDetail = &hookmonv1.PtraceDetail{
			Request:     evt.PtraceDetail.Request,
			RequestName: evt.PtraceDetail.RequestName,
			TargetPID:   evt.PtraceDetail.TargetPID,
			TargetComm:  evt.PtraceDetail.TargetComm,
			Addr:        evt.PtraceDetail.Addr,
		}
	}

	if evt.LibIntegrityDetail != nil {
		pe.LibIntegrityDetail = &hookmonv1.LibIntegrityDetail{
			LibraryPath: evt.LibIntegrityDetail.LibraryPath,
			Operation:   evt.LibIntegrityDetail.Operation,
			OldHash:     evt.LibIntegrityDetail.OldHash,
			NewHash:     evt.LibIntegrityDetail.NewHash,
			InLdCache:   evt.LibIntegrityDetail.InLdCache,
		}
	}

	return pe
}

func eventTypeToProto(et event.EventType) hookmonv1.EventType {
	switch et {
	case event.EventBPFLoad:
		return hookmonv1.EventType_EVENT_TYPE_BPF_LOAD
	case event.EventBPFAttach:
		return hookmonv1.EventType_EVENT_TYPE_BPF_ATTACH
	case event.EventExecInjection:
		return hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION
	case event.EventSHMCreate:
		return hookmonv1.EventType_EVENT_TYPE_SHM_CREATE
	case event.EventDlopen:
		return hookmonv1.EventType_EVENT_TYPE_DLOPEN
	case event.EventLinkerConfig:
		return hookmonv1.EventType_EVENT_TYPE_LINKER_CONFIG
	case event.EventPtraceInject:
		return hookmonv1.EventType_EVENT_TYPE_PTRACE_INJECT
	case event.EventLibIntegrity:
		return hookmonv1.EventType_EVENT_TYPE_LIB_INTEGRITY
	case event.EventAgentOffline:
		return hookmonv1.EventType_EVENT_TYPE_AGENT_OFFLINE
	case event.EventAgentRecovered:
		return hookmonv1.EventType_EVENT_TYPE_AGENT_RECOVERED
	default:
		return hookmonv1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}

func severityToProto(s event.Severity) hookmonv1.Severity {
	switch s {
	case event.SeverityInfo:
		return hookmonv1.Severity_SEVERITY_INFO
	case event.SeverityWarn:
		return hookmonv1.Severity_SEVERITY_WARN
	case event.SeverityAlert:
		return hookmonv1.Severity_SEVERITY_ALERT
	case event.SeverityCritical:
		return hookmonv1.Severity_SEVERITY_CRITICAL
	default:
		return hookmonv1.Severity_SEVERITY_UNSPECIFIED
	}
}
