package transport

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dlenrow/hookmon/agent/config"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/pkg/version"
)

const (
	// sendQueueSize bounds the messages waiting for the sender. At roughly
	// 1 KB per event this caps the backlog near 1 MB.
	sendQueueSize = 1024

	// shutdownGrace is how long a stream may outlive Run's context, so that
	// shutdown can half-close it and collect the server's last acks.
	shutdownGrace = 5 * time.Second
)

var (
	errNotConnected = errors.New("not connected")
	errQueueFull    = errors.New("send queue full")
)

// outbound is one queued message. A nil evt is a heartbeat, which the sender
// builds at send time so its counters are current.
type outbound struct {
	evt *event.HookEvent
}

// GRPCTransport streams events to the hookmon-server over mTLS gRPC.
//
// Run is the only goroutine that calls Send or CloseSend on the stream.
// SendEvent and SendHeartbeat are safe for concurrent use; they only enqueue
// onto a bounded queue that Run drains. Each stream also has one receive
// goroutine that drains the server's acks.
//
// The fallback log holds every event the server did not acknowledge:
//   - Stream down: SendEvent writes the event to the fallback log.
//   - Queue full: SendEvent writes the event to the fallback log instead of
//     blocking the sensor that produced it.
//   - Negative ack: the event is written to the fallback log.
//   - Stream breaks: events sent but not yet acked, and events still queued,
//     are written to the fallback log, then Run reconnects with backoff.
//
// The server may have stored an event whose ack was lost, so the fallback log
// can hold duplicates. It is not replayed to the server. Heartbeats never go
// to the fallback log; one that cannot be queued is dropped with an error.
type GRPCTransport struct {
	cfg      *config.AgentConfig
	logger   *zap.Logger
	fallback *FallbackLogger
	retry    RetryConfig
	queue    chan outbound

	// mu guards connected. enqueue holds it while it queues a message, so
	// once Run marks the stream down nothing new can enter the queue.
	mu        sync.Mutex
	connected bool

	// inflight holds events sent on the current stream and not yet acked.
	inflightMu sync.Mutex
	inflight   map[string]*event.HookEvent

	eventsSent uint64 // owned by the Run goroutine
	startTime  time.Time

	// sensors returns the sensor-registry snapshot each heartbeat carries.
	// Set before Run; nil sends heartbeats without one.
	sensors func() []event.SensorHealth
}

// session is one ClientConn and the event stream opened on it.
type session struct {
	conn      *grpc.ClientConn
	stream    hookmonv1.AgentService_StreamEventsClient
	cancel    context.CancelFunc
	stopTimer func() bool
	recvDone  chan struct{}
	recvErr   error // set before recvDone is closed
}

// NewGRPCTransport creates a new gRPC transport. retry sets the backoff Run
// uses between connection attempts.
func NewGRPCTransport(cfg *config.AgentConfig, logger *zap.Logger, retry RetryConfig) *GRPCTransport {
	return &GRPCTransport{
		cfg:       cfg,
		logger:    logger,
		fallback:  NewFallbackLogger(cfg.FallbackLogPath),
		retry:     retry,
		queue:     make(chan outbound, sendQueueSize),
		inflight:  make(map[string]*event.HookEvent),
		startTime: time.Now(),
	}
}

// SetSensorSource sets the function that supplies the sensor-registry
// snapshot sent with every heartbeat. It is called from Run's goroutine at
// send time, so it must be safe for concurrent use. Call it before Run.
func (t *GRPCTransport) SetSensorSource(fn func() []event.SensorHealth) {
	t.sensors = fn
}

// Run connects to the server and keeps an event stream open until ctx is
// cancelled. After any stream failure it reconnects with RetryLoop's
// exponential backoff. It returns nil once ctx is cancelled, and
// ErrNoIdentity at once if the bus has no client certificate and is not in
// insecure mode. Call Close only after Run has returned.
func (t *GRPCTransport) Run(ctx context.Context) error {
	// Never fall back to plaintext: without --insecure the bus needs a
	// client certificate, which EnsureIdentity provides.
	if !t.cfg.TLS.Insecure && t.cfg.TLS.CertFile == "" {
		return ErrNoIdentity
	}
	if t.cfg.TLS.Insecure {
		t.logger.Warn("insecure mode: connecting to the server without TLS; development only",
			zap.String("server", t.cfg.ServerAddr))
	}
	for {
		var s *session
		err := RetryLoop(ctx, t.retry, t.logger, func(ctx context.Context) error {
			var err error
			s, err = t.connect(ctx)
			return err
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		err = t.serve(ctx, s)
		if ctx.Err() != nil {
			return nil
		}
		t.logger.Warn("stream to server lost, reconnecting", zap.Error(err))

		// Pause before reconnecting so a server that accepts the stream and
		// then fails it at once cannot drive a tight reconnect loop.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(t.retry.InitialDelay):
		}
	}
}

// connect dials the server and opens the event stream. Each attempt gets a
// fresh ClientConn so that RetryLoop alone paces reconnection, without gRPC's
// own reconnect backoff on a reused conn stacked on top.
func (t *GRPCTransport) connect(ctx context.Context) (*session, error) {
	opts, err := t.dialOptions()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(t.cfg.ServerAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	// The stream is not derived from ctx: it is cancelled shutdownGrace after
	// ctx ends, which bounds shutdown even if Send or the dial is blocked.
	streamCtx, cancel := context.WithCancel(context.Background())
	stopTimer := context.AfterFunc(ctx, func() { time.AfterFunc(shutdownGrace, cancel) })

	stream, err := hookmonv1.NewAgentServiceClient(conn).StreamEvents(streamCtx)
	if err != nil {
		stopTimer()
		cancel()
		conn.Close()
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return &session{
		conn:      conn,
		stream:    stream,
		cancel:    cancel,
		stopTimer: stopTimer,
		recvDone:  make(chan struct{}),
	}, nil
}

// dialOptions returns mutual-TLS credentials, or plaintext only when
// TLS.Insecure is set.
func (t *GRPCTransport) dialOptions() ([]grpc.DialOption, error) {
	if t.cfg.TLS.Insecure {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	creds, err := hcrypto.LoadClientTLS(
		t.cfg.TLS.CertFile, t.cfg.TLS.KeyFile,
		t.cfg.TLS.CAFile, t.cfg.TLS.ServerName,
	)
	if err != nil {
		return nil, fmt.Errorf("load TLS credentials: %w", err)
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}, nil
}

// serve runs one stream until it breaks or ctx is cancelled, then tears it
// down and returns why it ended (nil on shutdown).
func (t *GRPCTransport) serve(ctx context.Context, s *session) error {
	go t.recvLoop(s)
	t.setConnected(true)
	t.logger.Info("connected to server", zap.String("addr", t.cfg.ServerAddr))

	err := t.sendLoop(ctx, s)

	// Mark the stream down first so the queue cannot refill while it drains.
	t.setConnected(false)
	if err == nil {
		// Shutdown: half-close so the server acks what it has and ends the
		// stream. The timer set in connect bounds the wait.
		_ = s.stream.CloseSend()
	} else {
		s.cancel()
	}
	<-s.recvDone
	s.stopTimer()
	s.cancel()
	s.conn.Close()

	t.flushInflight()
	t.drainQueue()
	return err
}

// sendLoop is the only caller of stream.Send. It returns nil when ctx is
// cancelled, or the error that broke the stream.
func (t *GRPCTransport) sendLoop(ctx context.Context, s *session) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.recvDone:
			return fmt.Errorf("receive: %w", s.recvErr)
		case m := <-t.queue:
			if err := t.send(s.stream, m); err != nil {
				return fmt.Errorf("send: %w", err)
			}
		}
	}
}

func (t *GRPCTransport) send(stream hookmonv1.AgentService_StreamEventsClient, m outbound) error {
	if m.evt == nil {
		hb := &hookmonv1.Heartbeat{
			HostId:        t.cfg.HostID,
			Timestamp:     timestamppb.Now(),
			AgentVersion:  version.Version,
			EventsSent:    t.eventsSent,
			UptimeSeconds: uint64(time.Since(t.startTime).Seconds()),
		}
		if t.sensors != nil {
			hb.Sensors = sensorsToProto(t.sensors())
		}
		return stream.Send(&hookmonv1.AgentMessage{
			Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: hb},
		})
	}

	// Track the event before sending it so its ack cannot arrive first. If
	// Send fails, it stays in inflight and serve writes it to the fallback log.
	t.inflightMu.Lock()
	t.inflight[m.evt.ID] = m.evt
	t.inflightMu.Unlock()

	msg := &hookmonv1.AgentMessage{
		Payload: &hookmonv1.AgentMessage_Event{Event: eventToProto(m.evt)},
	}
	if err := stream.Send(msg); err != nil {
		return err
	}
	t.eventsSent++
	return nil
}

// recvLoop drains server messages so the server's ack sends never stall on
// flow control. It records why Recv stopped, then closes recvDone.
func (t *GRPCTransport) recvLoop(s *session) {
	defer close(s.recvDone)
	for {
		msg, err := s.stream.Recv()
		if err != nil {
			s.recvErr = err
			return
		}
		ack := msg.GetAck()
		if ack == nil {
			continue
		}
		t.inflightMu.Lock()
		evt := t.inflight[ack.GetEventId()]
		delete(t.inflight, ack.GetEventId())
		t.inflightMu.Unlock()

		if !ack.GetAccepted() {
			t.logger.Warn("server rejected event, writing to fallback log",
				zap.String("event_id", ack.GetEventId()))
			if evt != nil {
				t.writeFallback(evt)
			}
		}
	}
}

func (t *GRPCTransport) setConnected(v bool) {
	t.mu.Lock()
	t.connected = v
	t.mu.Unlock()
}

// enqueue queues m for the sender without blocking.
func (t *GRPCTransport) enqueue(m outbound) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected {
		return errNotConnected
	}
	select {
	case t.queue <- m:
		return nil
	default:
		return errQueueFull
	}
}

// SendEvent queues an event for the server, or writes it to the fallback log
// if the stream is down or the queue is full.
func (t *GRPCTransport) SendEvent(evt *event.HookEvent) error {
	err := t.enqueue(outbound{evt: evt})
	if err == nil {
		return nil
	}
	if errors.Is(err, errQueueFull) {
		t.logger.Warn("send queue full, writing event to fallback log", zap.String("event_id", evt.ID))
	}
	return t.fallback.Write(evt)
}

// SendHeartbeat queues a heartbeat for the server. It returns an error if the
// stream is down or the queue is full.
func (t *GRPCTransport) SendHeartbeat() error {
	return t.enqueue(outbound{})
}

// flushInflight writes events the server never acked to the fallback log,
// oldest first.
func (t *GRPCTransport) flushInflight() {
	t.inflightMu.Lock()
	pending := make([]*event.HookEvent, 0, len(t.inflight))
	for _, evt := range t.inflight {
		pending = append(pending, evt)
	}
	t.inflight = make(map[string]*event.HookEvent)
	t.inflightMu.Unlock()

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Timestamp.Before(pending[j].Timestamp)
	})
	for _, evt := range pending {
		t.writeFallback(evt)
	}
}

// drainQueue writes queued events to the fallback log and discards queued
// heartbeats. The stream must already be marked down so the queue cannot
// refill.
func (t *GRPCTransport) drainQueue() {
	for {
		select {
		case m := <-t.queue:
			if m.evt != nil {
				t.writeFallback(m.evt)
			}
		default:
			return
		}
	}
}

func (t *GRPCTransport) writeFallback(evt *event.HookEvent) {
	if err := t.fallback.Write(evt); err != nil {
		t.logger.Error("fallback log write failed", zap.String("event_id", evt.ID), zap.Error(err))
	}
}

// Close writes anything still queued to the fallback log and closes it.
// Call it only after Run has returned and no goroutine is still sending.
func (t *GRPCTransport) Close() error {
	t.setConnected(false)
	t.flushInflight()
	t.drainQueue()
	return t.fallback.Close()
}

// IsConnected reports whether the transport has an active connection.
func (t *GRPCTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected
}

func eventToProto(evt *event.HookEvent) *hookmonv1.HookEvent {
	pe := &hookmonv1.HookEvent{
		Id:          evt.ID,
		Timestamp:   timestamppb.New(evt.Timestamp),
		HostId:      evt.HostID,
		Hostname:    evt.Hostname,
		EventType:   eventTypeToProto(evt.EventType),
		Severity:    severityToProto(evt.Severity),
		Pid:         evt.PID,
		Ppid:        evt.PPID,
		Uid:         evt.UID,
		Gid:         evt.GID,
		Comm:        evt.Comm,
		Cmdline:     evt.Cmdline,
		ExePath:     evt.ExePath,
		ExeHash:     evt.ExeHash,
		CgroupPath:  evt.CgroupPath,
		ContainerId: evt.ContainerID,
		Namespace:   evt.Namespace,
	}

	if evt.BPFDetail != nil {
		pe.BpfDetail = &hookmonv1.BPFDetail{
			BpfCmd:       evt.BPFDetail.BPFCommand,
			ProgType:     evt.BPFDetail.ProgType,
			ProgName:     evt.BPFDetail.ProgName,
			AttachType:   evt.BPFDetail.AttachType,
			TargetFd:     evt.BPFDetail.TargetFD,
			InsnCount:    evt.BPFDetail.InsnCount,
			ProgHash:     evt.BPFDetail.ProgHash,
			ProgId:       evt.BPFDetail.ProgID,
			CreatedByUid: evt.BPFDetail.CreatedByUID,
			AttachTarget: evt.BPFDetail.AttachTarget,
		}
		if evt.BPFDetail.LoadTime != nil {
			pe.BpfDetail.LoadTime = timestamppb.New(*evt.BPFDetail.LoadTime)
		}
	}

	if evt.BPFInventoryDetail != nil {
		pe.BpfInventoryDetail = &hookmonv1.BPFInventoryDetail{
			ScanId:    evt.BPFInventoryDetail.ScanID,
			Summary:   evt.BPFInventoryDetail.Summary,
			ProgCount: evt.BPFInventoryDetail.ProgCount,
			ByType:    evt.BPFInventoryDetail.ByType,
		}
	}

	if evt.ExecInjectionDetail != nil {
		pe.ExecInjectionDetail = &hookmonv1.ExecInjectionDetail{
			LibraryPath:    evt.ExecInjectionDetail.LibraryPath,
			LibraryHash:    evt.ExecInjectionDetail.LibraryHash,
			TargetBinary:   evt.ExecInjectionDetail.TargetBinary,
			SetBy:          evt.ExecInjectionDetail.SetBy,
			EnvVar:         evt.ExecInjectionDetail.EnvVar,
			ScanTruncated:  evt.ExecInjectionDetail.ScanTruncated,
			ValueTruncated: evt.ExecInjectionDetail.ValueTruncated,
		}
	}

	if evt.SHMDetail != nil {
		pe.ShmDetail = &hookmonv1.SHMDetail{
			ShmName: evt.SHMDetail.SHMName,
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
			TargetPid:   evt.PtraceDetail.TargetPID,
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

	if evt.ElfRpathDetail != nil {
		entries := make([]*hookmonv1.RpathEntry, len(evt.ElfRpathDetail.Entries))
		for i, e := range evt.ElfRpathDetail.Entries {
			entries[i] = &hookmonv1.RpathEntry{
				Path:    e.Path,
				Risk:    string(e.Risk),
				Reason:  e.Reason,
				Exists:  e.Exists,
				IsRpath: e.IsRpath,
			}
		}
		pe.ElfRpathDetail = &hookmonv1.ElfRpathDetail{
			HasRpath:       evt.ElfRpathDetail.HasRpath,
			HasRunpath:     evt.ElfRpathDetail.HasRunpath,
			RpathRaw:       evt.ElfRpathDetail.RpathRaw,
			RunpathRaw:     evt.ElfRpathDetail.RunpathRaw,
			Entries:        entries,
			HighestRisk:    string(evt.ElfRpathDetail.HighestRisk),
			UsesOrigin:     evt.ElfRpathDetail.UsesOrigin,
			UsesDeprecated: evt.ElfRpathDetail.UsesDeprecated,
			IsSetuid:       evt.ElfRpathDetail.IsSetuid,
		}
	}

	return pe
}

// sensorsToProto converts a sensor-registry snapshot for a heartbeat.
func sensorsToProto(in []event.SensorHealth) []*hookmonv1.SensorHealth {
	if len(in) == 0 {
		return nil
	}
	out := make([]*hookmonv1.SensorHealth, len(in))
	for i, s := range in {
		out[i] = &hookmonv1.SensorHealth{Name: s.Name, Status: s.Status, Reason: s.Reason}
	}
	return out
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
	case event.EventElfRpath:
		return hookmonv1.EventType_EVENT_TYPE_ELF_RPATH
	case event.EventBPFInventory:
		return hookmonv1.EventType_EVENT_TYPE_BPF_INVENTORY
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
