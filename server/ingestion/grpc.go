// Package ingestion implements the gRPC server that receives event streams
// and heartbeats from hookmon agents deployed on monitored hosts.
package ingestion

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/google/uuid"
)

// Store is the interface that the ingestion layer requires for persistence.
// Implementations are provided by the server/store package.
type Store interface {
	InsertEvent(ctx context.Context, evt *event.HookEvent) error
	UpsertHost(ctx context.Context, host *event.Host) error
	UpdateHostHeartbeat(ctx context.Context, hostID string, ts time.Time) error
}

// PolicyEngine evaluates events against the allowlist and returns a policy result.
type PolicyEngine interface {
	Evaluate(evt *event.HookEvent) *event.PolicyResult
}

// Connector is a downstream consumer of processed events (SIEM, webhook, etc.).
type Connector interface {
	Send(evt *event.HookEvent) error
}

// hostState tracks per-host liveness metadata protected by IngestionServer's mutex.
type hostState struct {
	lastHeartbeat time.Time
	agentVersion  string
}

// IngestionServer implements the hookmonv1.AgentServiceServer interface,
// handling bidirectional event streams and agent enrollment.
type IngestionServer struct {
	hookmonv1.UnimplementedAgentServiceServer

	store        Store
	policyEngine PolicyEngine
	logger       *zap.Logger
	connectors   []Connector
	rateLimiter  *RateLimiter

	// eventCh broadcasts processed events for WebSocket consumers.
	// Sent events have already been validated, enriched with policy results,
	// and persisted.
	eventCh chan *event.HookEvent

	// hostTracker keeps an in-memory map of host ID to liveness state.
	// Protected by hostMu.
	hostMu      sync.RWMutex
	hostTracker map[string]*hostState

	// enrollmentToken is the shared secret agents must present during enrollment.
	enrollmentToken string

	// caCert and caKey are used to sign agent CSRs during enrollment.
	// In production these would be backed by a proper CA; here we store the
	// raw PEM bytes for the signing operation.
	caCert []byte
	caKey  []byte
}

// IngestionConfig holds the parameters needed to construct an IngestionServer.
type IngestionConfig struct {
	Store           Store
	PolicyEngine    PolicyEngine
	Logger          *zap.Logger
	Connectors      []Connector
	RateLimiter     *RateLimiter
	EnrollmentToken string
	CACert          []byte
	CAKey           []byte

	// EventChannelSize controls the buffer size of the event broadcast channel.
	// Defaults to 256 if zero.
	EventChannelSize int
}

// NewIngestionServer creates a fully initialized IngestionServer ready for
// registration with a grpc.Server.
func NewIngestionServer(cfg IngestionConfig) *IngestionServer {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	chanSize := cfg.EventChannelSize
	if chanSize <= 0 {
		chanSize = 256
	}
	return &IngestionServer{
		store:           cfg.Store,
		policyEngine:    cfg.PolicyEngine,
		logger:          cfg.Logger,
		connectors:      cfg.Connectors,
		rateLimiter:     cfg.RateLimiter,
		eventCh:         make(chan *event.HookEvent, chanSize),
		hostTracker:     make(map[string]*hostState),
		enrollmentToken: cfg.EnrollmentToken,
		caCert:          cfg.CACert,
		caKey:           cfg.CAKey,
	}
}

// GetEventChannel returns a read-only channel of processed events for use by
// the WebSocket real-time feed. Events are delivered on a best-effort basis;
// if the consumer is slow, events may be dropped.
func (s *IngestionServer) GetEventChannel() <-chan *event.HookEvent {
	return s.eventCh
}

// StreamEvents implements the bidirectional streaming RPC through which agents
// deliver events and heartbeats. The server processes each incoming AgentMessage,
// applying validation, rate limiting, policy evaluation, storage, and fan-out
// before sending an acknowledgement back to the agent.
func (s *IngestionServer) StreamEvents(stream hookmonv1.AgentService_StreamEventsServer) error {
	peerAddr := "unknown"
	if p, ok := peer.FromContext(stream.Context()); ok {
		peerAddr = p.Addr.String()
	}
	s.logger.Info("agent stream connected", zap.String("peer", peerAddr))

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("agent stream closed cleanly", zap.String("peer", peerAddr))
			return nil
		}
		if err != nil {
			s.logger.Warn("agent stream recv error",
				zap.String("peer", peerAddr),
				zap.Error(err),
			)
			return err
		}

		switch {
		case msg.Event != nil:
			if err := s.handleEvent(stream, msg.Event); err != nil {
				s.logger.Error("failed to handle event",
					zap.String("peer", peerAddr),
					zap.Error(err),
				)
				// Send a negative ack but keep the stream open.
				if sendErr := s.sendEventAck(stream, msg.Event.ID, false); sendErr != nil {
					return sendErr
				}
			}

		case msg.Heartbeat != nil:
			s.handleHeartbeat(stream.Context(), msg.Heartbeat)

		default:
			s.logger.Warn("received empty agent message", zap.String("peer", peerAddr))
		}
	}
}

// handleEvent processes a single event from the agent stream. It validates
// the event, checks rate limits, evaluates policy, persists the event, fans
// out to connectors and the WebSocket channel, and sends an ack back to
// the agent.
func (s *IngestionServer) handleEvent(stream hookmonv1.AgentService_StreamEventsServer, protoEvt *hookmonv1.HookEvent) error {
	// Convert from proto representation to canonical event model.
	evt := protoToEvent(protoEvt)

	// Validate required fields.
	if err := ValidateEvent(evt); err != nil {
		s.logger.Warn("event validation failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("validation: %w", err)
	}

	// Apply per-host rate limiting.
	if s.rateLimiter != nil && !s.rateLimiter.Allow(evt.HostID) {
		s.logger.Warn("event rate limited",
			zap.String("host_id", evt.HostID),
			zap.String("event_id", evt.ID),
		)
		return fmt.Errorf("rate limited for host %s", evt.HostID)
	}

	// Evaluate against the policy/allowlist engine.
	if s.policyEngine != nil {
		result := s.policyEngine.Evaluate(evt)
		evt.PolicyResult = result
	}

	// Persist the event.
	ctx := stream.Context()
	if s.store != nil {
		if err := s.store.InsertEvent(ctx, evt); err != nil {
			s.logger.Error("failed to insert event",
				zap.String("event_id", evt.ID),
				zap.Error(err),
			)
			return fmt.Errorf("store insert: %w", err)
		}
	}

	// Fan out to SIEM connectors. Errors are logged but do not fail the
	// overall event processing — the event is already persisted.
	for _, c := range s.connectors {
		if err := c.Send(evt); err != nil {
			s.logger.Warn("connector send failed",
				zap.String("event_id", evt.ID),
				zap.Error(err),
			)
		}
	}

	// Broadcast to the WebSocket event channel (non-blocking).
	select {
	case s.eventCh <- evt:
	default:
		s.logger.Debug("event channel full, dropping broadcast",
			zap.String("event_id", evt.ID),
		)
	}

	// Send positive acknowledgement back to the agent.
	if err := s.sendEventAck(stream, evt.ID, true); err != nil {
		return fmt.Errorf("send ack: %w", err)
	}

	s.logger.Debug("event processed",
		zap.String("event_id", evt.ID),
		zap.String("host_id", evt.HostID),
		zap.String("event_type", string(evt.EventType)),
	)

	return nil
}

// handleHeartbeat updates the in-memory host tracker and persists the
// heartbeat timestamp to the store.
func (s *IngestionServer) handleHeartbeat(ctx context.Context, hb *hookmonv1.Heartbeat) {
	if hb.HostID == "" {
		s.logger.Warn("received heartbeat with empty host_id")
		return
	}

	now := hb.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Update in-memory tracker.
	s.hostMu.Lock()
	s.hostTracker[hb.HostID] = &hostState{
		lastHeartbeat: now,
		agentVersion:  hb.AgentVersion,
	}
	s.hostMu.Unlock()

	// Persist heartbeat to the store.
	if s.store != nil {
		if err := s.store.UpdateHostHeartbeat(ctx, hb.HostID, now); err != nil {
			s.logger.Error("failed to update host heartbeat",
				zap.String("host_id", hb.HostID),
				zap.Error(err),
			)
		}
	}

	s.logger.Debug("heartbeat received",
		zap.String("host_id", hb.HostID),
		zap.String("agent_version", hb.AgentVersion),
		zap.Uint64("events_sent", hb.EventsSent),
	)
}

// sendEventAck sends an EventAck message back to the agent over the stream.
func (s *IngestionServer) sendEventAck(stream hookmonv1.AgentService_StreamEventsServer, eventID string, accepted bool) error {
	return stream.Send(&hookmonv1.ServerMessage{
		Ack: &hookmonv1.EventAck{
			EventID:  eventID,
			Accepted: accepted,
		},
	})
}

// Enroll handles agent enrollment. It validates the enrollment token, signs
// the agent's CSR, registers the host in the store, and returns the signed
// certificate along with the CA certificate so the agent can establish mTLS.
func (s *IngestionServer) Enroll(ctx context.Context, req *hookmonv1.EnrollRequest) (*hookmonv1.EnrollResponse, error) {
	// Validate the enrollment token.
	if req.EnrollmentToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "enrollment token is required")
	}
	if req.EnrollmentToken != s.enrollmentToken {
		s.logger.Warn("enrollment rejected: invalid token",
			zap.String("hostname", req.Hostname),
		)
		return nil, status.Errorf(codes.PermissionDenied, "invalid enrollment token")
	}

	// Validate request fields.
	if req.Hostname == "" {
		return nil, status.Errorf(codes.InvalidArgument, "hostname is required")
	}
	if len(req.CSR) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "CSR is required")
	}

	// Generate a unique host ID for this agent.
	hostID := uuid.New().String()

	// Sign the CSR.
	// In a production implementation this would parse the CSR, validate it,
	// and sign it with the CA private key. For now we return the CA cert
	// as a placeholder for the signed cert — the real signing logic belongs
	// in pkg/crypto and will be wired in when that package is implemented.
	signedCert := s.caCert // placeholder: replace with real CSR signing

	// Register the host in the store.
	now := time.Now().UTC()
	host := &event.Host{
		ID:            hostID,
		Hostname:      req.Hostname,
		AgentVersion:  req.AgentVersion,
		OSInfo:        req.OSInfo,
		Status:        event.HostOnline,
		EnrolledAt:    now,
		LastHeartbeat: now,
	}

	if s.store != nil {
		if err := s.store.UpsertHost(ctx, host); err != nil {
			s.logger.Error("failed to register host during enrollment",
				zap.String("hostname", req.Hostname),
				zap.Error(err),
			)
			return nil, status.Errorf(codes.Internal, "failed to register host: %v", err)
		}
	}

	// Track the new host in memory.
	s.hostMu.Lock()
	s.hostTracker[hostID] = &hostState{
		lastHeartbeat: now,
		agentVersion:  req.AgentVersion,
	}
	s.hostMu.Unlock()

	s.logger.Info("agent enrolled",
		zap.String("host_id", hostID),
		zap.String("hostname", req.Hostname),
		zap.String("agent_version", req.AgentVersion),
	)

	return &hookmonv1.EnrollResponse{
		HostID:     hostID,
		SignedCert: signedCert,
		CACert:     s.caCert,
	}, nil
}

// GetHostLastHeartbeat returns the last heartbeat time for a host.
// Returns zero time and false if the host is not tracked.
func (s *IngestionServer) GetHostLastHeartbeat(hostID string) (time.Time, bool) {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	hs, ok := s.hostTracker[hostID]
	if !ok {
		return time.Time{}, false
	}
	return hs.lastHeartbeat, true
}

// TrackedHostCount returns the number of hosts currently being tracked.
func (s *IngestionServer) TrackedHostCount() int {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	return len(s.hostTracker)
}

// ---------------------------------------------------------------------------
// Proto-to-domain conversion
// ---------------------------------------------------------------------------

// protoEventTypeToEventType maps proto EventType enum values to the canonical
// event.EventType string constants used throughout the domain layer.
var protoEventTypeToEventType = map[hookmonv1.EventType]event.EventType{
	hookmonv1.EventType_EVENT_TYPE_BPF_LOAD:        event.EventBPFLoad,
	hookmonv1.EventType_EVENT_TYPE_BPF_ATTACH:      event.EventBPFAttach,
	hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION:   event.EventExecInjection,
	hookmonv1.EventType_EVENT_TYPE_SHM_CREATE:      event.EventSHMCreate,
	hookmonv1.EventType_EVENT_TYPE_DLOPEN:          event.EventDlopen,
	hookmonv1.EventType_EVENT_TYPE_LINKER_CONFIG:    event.EventLinkerConfig,
	hookmonv1.EventType_EVENT_TYPE_PTRACE_INJECT:   event.EventPtraceInject,
	hookmonv1.EventType_EVENT_TYPE_LIB_INTEGRITY:   event.EventLibIntegrity,
	hookmonv1.EventType_EVENT_TYPE_AGENT_OFFLINE:   event.EventAgentOffline,
	hookmonv1.EventType_EVENT_TYPE_AGENT_RECOVERED: event.EventAgentRecovered,
}

// protoToEvent converts a proto HookEvent to the canonical event.HookEvent
// used by the server's domain layer (store, policy engine, connectors).
func protoToEvent(pe *hookmonv1.HookEvent) *event.HookEvent {
	if pe == nil {
		return nil
	}

	evt := &event.HookEvent{
		ID:          pe.ID,
		Timestamp:   pe.Timestamp,
		HostID:      pe.HostID,
		Hostname:    pe.Hostname,
		PID:         pe.PID,
		PPID:        pe.PPID,
		UID:         pe.UID,
		GID:         pe.GID,
		Comm:        pe.Comm,
		Cmdline:     pe.Cmdline,
		ExePath:     pe.ExePath,
		ExeHash:     pe.ExeHash,
		CgroupPath:  pe.CgroupPath,
		ContainerID: pe.ContainerID,
		Namespace:   pe.Namespace,
	}

	// Map proto enum to domain string type.
	if mapped, ok := protoEventTypeToEventType[pe.EventType]; ok {
		evt.EventType = mapped
	} else {
		evt.EventType = event.EventType(pe.EventType.String())
	}

	// Map proto severity enum to domain string severity.
	switch pe.Severity {
	case hookmonv1.Severity_SEVERITY_INFO:
		evt.Severity = event.SeverityInfo
	case hookmonv1.Severity_SEVERITY_WARN:
		evt.Severity = event.SeverityWarn
	case hookmonv1.Severity_SEVERITY_ALERT:
		evt.Severity = event.SeverityAlert
	case hookmonv1.Severity_SEVERITY_CRITICAL:
		evt.Severity = event.SeverityCritical
	default:
		evt.Severity = event.SeverityInfo
	}

	// Convert type-specific detail payloads.
	if pe.BPFDetail != nil {
		evt.BPFDetail = &event.BPFDetail{
			BPFCommand: pe.BPFDetail.BPFCommand,
			ProgType:   pe.BPFDetail.ProgType,
			ProgName:   pe.BPFDetail.ProgName,
			AttachType: pe.BPFDetail.AttachType,
			TargetFD:   pe.BPFDetail.TargetFD,
			InsnCount:  pe.BPFDetail.InsnCount,
			ProgHash:   pe.BPFDetail.ProgHash,
		}
	}
	if pe.ExecInjectionDetail != nil {
		evt.ExecInjectionDetail = &event.ExecInjectionDetail{
			LibraryPath:  pe.ExecInjectionDetail.LibraryPath,
			LibraryHash:  pe.ExecInjectionDetail.LibraryHash,
			TargetBinary: pe.ExecInjectionDetail.TargetBinary,
			SetBy:        pe.ExecInjectionDetail.SetBy,
			EnvVar:       pe.ExecInjectionDetail.EnvVar,
		}
	}
	if pe.SHMDetail != nil {
		evt.SHMDetail = &event.SHMDetail{
			SHMName: pe.SHMDetail.SHMName,
			Size:    pe.SHMDetail.Size,
			Pattern: pe.SHMDetail.Pattern,
		}
	}
	if pe.DlopenDetail != nil {
		evt.DlopenDetail = &event.DlopenDetail{
			LibraryPath: pe.DlopenDetail.LibraryPath,
			LibraryHash: pe.DlopenDetail.LibraryHash,
			Flags:       int(pe.DlopenDetail.Flags),
		}
	}
	if pe.LinkerConfigDetail != nil {
		evt.LinkerConfigDetail = &event.LinkerConfigDetail{
			FilePath:  pe.LinkerConfigDetail.FilePath,
			Operation: pe.LinkerConfigDetail.Operation,
			OldHash:   pe.LinkerConfigDetail.OldHash,
			NewHash:   pe.LinkerConfigDetail.NewHash,
		}
	}
	if pe.PtraceDetail != nil {
		evt.PtraceDetail = &event.PtraceDetail{
			Request:     pe.PtraceDetail.Request,
			RequestName: pe.PtraceDetail.RequestName,
			TargetPID:   pe.PtraceDetail.TargetPID,
			TargetComm:  pe.PtraceDetail.TargetComm,
			Addr:        pe.PtraceDetail.Addr,
		}
	}
	if pe.LibIntegrityDetail != nil {
		evt.LibIntegrityDetail = &event.LibIntegrityDetail{
			LibraryPath: pe.LibIntegrityDetail.LibraryPath,
			Operation:   pe.LibIntegrityDetail.Operation,
			OldHash:     pe.LibIntegrityDetail.OldHash,
			NewHash:     pe.LibIntegrityDetail.NewHash,
			InLdCache:   pe.LibIntegrityDetail.InLdCache,
		}
	}

	return evt
}
