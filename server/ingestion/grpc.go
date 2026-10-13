// Package ingestion implements the gRPC server that receives event streams
// and heartbeats from hookmon agents deployed on monitored hosts.
package ingestion

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
)

// Store is the interface that the ingestion layer requires for persistence.
// Implementations are provided by the server/store package.
type Store interface {
	InsertEvent(ctx context.Context, evt *event.HookEvent) error
	// UpdateHostHeartbeat records a heartbeat from an enrolled host and marks
	// it online. It returns an error if the host is not enrolled.
	UpdateHostHeartbeat(ctx context.Context, hb *event.HostHeartbeat) error
}

// HeartbeatRecorder is implemented by a Store that can report what a
// heartbeat changed. The ingestion server then uses RecordHeartbeat instead
// of UpdateHostHeartbeat, and raises AGENT_RECOVERED when a host the
// watchdog marked UNRESPONSIVE (or OFFLINE) heartbeats again.
type HeartbeatRecorder interface {
	// RecordHeartbeat does what UpdateHostHeartbeat does, in one statement,
	// and returns the host's status and last heartbeat from before it.
	RecordHeartbeat(ctx context.Context, hb *event.HostHeartbeat) (HeartbeatChange, error)
}

// HeartbeatChange is a host's state from before a heartbeat was recorded.
type HeartbeatChange struct {
	PrevStatus        event.HostStatus
	PrevHeartbeat     time.Time
	PrevKernelRelease string
	KernelChanged     bool
}

// HostLookup is implemented by a Store that can return an enrolled host.
// The ingestion server uses it to name a certificate's host by the hostname
// recorded at enrollment, rather than by the hostname each message carries.
type HostLookup interface {
	GetHost(ctx context.Context, id string) (*event.Host, error)
}

// PolicyEngine evaluates events against the allowlist and returns a policy result.
type PolicyEngine interface {
	Evaluate(evt *event.HookEvent) *event.PolicyResult
}

// Connector is a downstream consumer of processed events (SIEM, webhook, etc.).
type Connector interface {
	Send(evt *event.HookEvent) error
}

// StatusSink receives the host status events the server raises itself
// (AGENT_RECOVERED here, AGENT_OFFLINE in the watchdog). The connector
// dispatcher implements it and sends them to every connector.
type StatusSink interface {
	Dispatch(evt *event.HookEvent)
}

// hostState tracks per-host liveness metadata protected by IngestionServer's mutex.
type hostState struct {
	lastHeartbeat  time.Time
	agentVersion   string
	shutdownReason string
	shutdownAt     time.Time
	lastMarker     time.Time
}

// broadcastDropLogEvery bounds how often a full broadcast channel is logged.
const broadcastDropLogEvery = 10 * time.Second

// hostnameRetry is how long a stream waits before it looks up its host's
// enrolled hostname again after a failed lookup.
const hostnameRetry = 30 * time.Second

// IngestionServer implements the event stream of hookmonv1.AgentService on
// the mutual-TLS listener. Enrollment is served separately, by Enroller.
//
// The host ID of every event and heartbeat is the CN of the bus's verified
// client certificate. A host ID inside a message is ignored, so one host
// cannot send as another. The hostname stored with each event is the one
// recorded when that host enrolled, not the one in the message. A stream
// without a verified host certificate is refused, unless Insecure is set.
type IngestionServer struct {
	hookmonv1.UnimplementedAgentServiceServer

	store        Store
	policyEngine PolicyEngine
	logger       *zap.Logger
	connectors   []Connector
	statusSink   StatusSink
	rateLimiter  *RateLimiter
	insecure     bool
	now          func() time.Time

	// eventCh broadcasts processed events for WebSocket consumers.
	// Sent events have already been validated, enriched with policy results,
	// and persisted. When it is full, Publish drops the event and counts it.
	eventCh chan *event.HookEvent

	broadcastDrops atomic.Uint64
	// dropped counts events evaluated as a repeat or allowed, and so not
	// stored, shown or sent.
	dropped        atomic.Uint64
	dropLogMu      sync.Mutex
	dropLogAt      time.Time
	dropsAtLastLog uint64

	// hostTracker keeps an in-memory map of host ID to liveness state.
	// Protected by hostMu.
	hostMu      sync.RWMutex
	hostTracker map[string]*hostState
}

// IngestionConfig holds the parameters needed to construct an IngestionServer.
type IngestionConfig struct {
	Store        Store
	PolicyEngine PolicyEngine
	Logger       *zap.Logger
	Connectors   []Connector
	// StatusSink receives AGENT_RECOVERED. Nil: the event is stored and
	// published to the WebSocket feed only.
	StatusSink  StatusSink
	RateLimiter *RateLimiter

	// Insecure accepts streams that carry no verified client certificate and
	// takes the host ID from each message instead. Any host can then report
	// as any other. Only for a server running without TLS, in development.
	Insecure bool

	// EventChannelSize controls the buffer size of the event broadcast channel.
	// Defaults to 256 if zero.
	EventChannelSize int

	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// NewIngestionServer creates a fully initialized IngestionServer ready for
// registration with a grpc.Server.
func NewIngestionServer(cfg IngestionConfig) *IngestionServer {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	chanSize := cfg.EventChannelSize
	if chanSize <= 0 {
		chanSize = 256
	}
	return &IngestionServer{
		store:        cfg.Store,
		policyEngine: cfg.PolicyEngine,
		logger:       cfg.Logger,
		connectors:   cfg.Connectors,
		statusSink:   cfg.StatusSink,
		rateLimiter:  cfg.RateLimiter,
		insecure:     cfg.Insecure,
		now:          cfg.Now,
		eventCh:      make(chan *event.HookEvent, chanSize),
		hostTracker:  make(map[string]*hostState),
	}
}

// GetEventChannel returns a read-only channel of processed events for use by
// the WebSocket real-time feed. Events are delivered on a best-effort basis;
// if the consumer is slow, events are dropped and counted (BroadcastDrops).
func (s *IngestionServer) GetEventChannel() <-chan *event.HookEvent {
	return s.eventCh
}

// Publish offers a stored event to the WebSocket feed without blocking. If
// the feed's buffer is full the event is dropped: the count goes up, and a
// warning is logged at most once per broadcastDropLogEvery. The event is
// still in the store and with the connectors.
func (s *IngestionServer) Publish(evt *event.HookEvent) {
	select {
	case s.eventCh <- evt:
		return
	default:
	}
	total := s.broadcastDrops.Add(1)
	s.dropLogMu.Lock()
	defer s.dropLogMu.Unlock()
	now := s.now()
	if !s.dropLogAt.IsZero() && now.Sub(s.dropLogAt) < broadcastDropLogEvery {
		return
	}
	s.logger.Warn("WebSocket feed buffer full; events dropped from the live feed (they are stored)",
		zap.Uint64("dropped_since_last_warning", total-s.dropsAtLastLog),
		zap.Uint64("dropped_total", total),
		zap.String("last_dropped_event_id", evt.ID),
	)
	s.dropLogAt = now
	s.dropsAtLastLog = total
}

// BroadcastDrops returns how many events Publish has dropped because the
// WebSocket feed's buffer was full.
func (s *IngestionServer) BroadcastDrops() uint64 {
	return s.broadcastDrops.Load()
}

// Dropped returns how many events were evaluated as a repeat of a PENDING
// new hook or as allowed, and so were not stored, shown or sent.
func (s *IngestionServer) Dropped() uint64 {
	return s.dropped.Load()
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

	id, err := s.identify(stream.Context())
	if err != nil {
		s.logger.Warn("agent stream refused", zap.String("peer", peerAddr), zap.Error(err))
		return status.Errorf(codes.Unauthenticated, "%v", err)
	}
	s.logger.Info("agent stream connected", zap.String("peer", peerAddr), zap.String("host_id", id.hostID),
		zap.String("hostname", id.hostname))

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
		case msg.GetEvent() != nil:
			if err := s.handleEvent(stream, id, msg.GetEvent()); err != nil {
				s.logger.Error("failed to handle event",
					zap.String("peer", peerAddr),
					zap.Error(err),
				)
				// Send a negative ack but keep the stream open.
				if sendErr := s.sendEventAck(stream, msg.GetEvent().GetId(), false); sendErr != nil {
					return sendErr
				}
			}

		case msg.GetHeartbeat() != nil:
			s.handleHeartbeat(stream.Context(), id, msg.GetHeartbeat())

		case msg.GetShutdown() != nil:
			s.handleShutdown(stream.Context(), id, msg.GetShutdown())

		case msg.GetMarker() != nil:
			s.handleMarker(id)

		default:
			s.logger.Warn("received empty agent message", zap.String("peer", peerAddr))
		}
	}
}

// streamIdentity is who is on the other end of one stream.
type streamIdentity struct {
	// hostID is the CN of the verified client certificate. It is empty only
	// on an Insecure server for a peer without one; the host ID in each
	// message is then used as sent.
	hostID string
	// limitKey is what the rate limiter counts this stream's events
	// against: the certificate's host ID, or on an Insecure server without
	// one, the peer's IP address. Never a value from a message.
	limitKey string
	// hostname is the hostname recorded when hostID enrolled. Empty until
	// it has been looked up, and in insecure mode without a certificate.
	hostname string
	// lookedUp is when the hostname was last looked up without success;
	// zero before the first attempt.
	lookedUp time.Time
	// mismatchLogged and hostnameLogged limit the "message names another
	// host" warnings to once per stream.
	mismatchLogged bool
	hostnameLogged bool
}

// identify returns the host ID from the stream's verified client
// certificate, and that host's enrolled hostname. Without a certificate,
// the stream is refused unless the server is Insecure.
func (s *IngestionServer) identify(ctx context.Context) (*streamIdentity, error) {
	hostID, err := hcrypto.HostIDFromPeer(ctx)
	if err == nil {
		id := &streamIdentity{hostID: hostID, limitKey: hostID}
		s.lookupHostname(ctx, id)
		return id, nil
	}
	if s.insecure {
		return &streamIdentity{limitKey: "peer:" + peerIP(ctx)}, nil
	}
	return nil, err
}

// lookupHostname fills id.hostname from the host's enrollment record, if
// the store can look hosts up. After a failure it tries again no sooner
// than hostnameRetry later.
func (s *IngestionServer) lookupHostname(ctx context.Context, id *streamIdentity) {
	if id.hostID == "" || id.hostname != "" {
		return
	}
	lookup, ok := s.store.(HostLookup)
	if !ok {
		return
	}
	now := s.now()
	if !id.lookedUp.IsZero() && now.Sub(id.lookedUp) < hostnameRetry {
		return
	}
	h, err := lookup.GetHost(ctx, id.hostID)
	if err != nil || h == nil || h.Hostname == "" {
		id.lookedUp = now
		s.logger.Warn("no enrolled hostname for this certificate's host; its events are stored without one",
			zap.String("host_id", id.hostID), zap.Error(err))
		return
	}
	id.hostname = h.Hostname
}

// resolve returns the host ID to record for a message that names claimed.
func (s *IngestionServer) resolve(id *streamIdentity, claimed, what string) string {
	if id.hostID == "" {
		return claimed
	}
	if claimed != "" && claimed != id.hostID && !id.mismatchLogged {
		id.mismatchLogged = true
		s.logger.Warn("message names a different host than its certificate; using the certificate's",
			zap.String("host_id", id.hostID),
			zap.String("claimed_host_id", claimed),
			zap.String("message", what),
		)
	}
	return id.hostID
}

// resolveHostname returns the hostname to record for an event whose
// message says claimed: the enrolled hostname for a certificate's host,
// or claimed on an Insecure stream without a certificate.
func (s *IngestionServer) resolveHostname(ctx context.Context, id *streamIdentity, claimed string) string {
	if id.hostID == "" {
		return claimed
	}
	s.lookupHostname(ctx, id)
	if id.hostname != "" && claimed != "" && claimed != id.hostname && !id.hostnameLogged {
		id.hostnameLogged = true
		s.logger.Warn("bus reports a different hostname than it enrolled with; recording the enrolled one",
			zap.String("host_id", id.hostID),
			zap.String("enrolled_hostname", id.hostname),
			zap.String("reported_hostname", claimed),
		)
	}
	return id.hostname
}

// handleEvent processes a single event from the agent stream. It validates
// the event, checks rate limits, evaluates policy, persists the event, fans
// out to connectors and the WebSocket channel, and sends an ack back to
// the agent.
func (s *IngestionServer) handleEvent(stream hookmonv1.AgentService_StreamEventsServer, id *streamIdentity, protoEvt *hookmonv1.HookEvent) error {
	ctx := stream.Context()

	// Convert from proto representation to canonical event model.
	evt := protoToEvent(protoEvt)
	evt.HostID = s.resolve(id, evt.HostID, "event")
	evt.Hostname = s.resolveHostname(ctx, id, evt.Hostname)

	// Validate required fields.
	if err := ValidateEvent(evt); err != nil {
		s.logger.Warn("event validation failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("validation: %w", err)
	}

	// Apply per-host rate limiting, keyed by the authenticated identity.
	if s.rateLimiter != nil && !s.rateLimiter.Allow(id.limitKey) {
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

	// A repeat of a new hook still waiting for a decision, and an allowed
	// hook, are not stored, shown or sent: the engine has counted a repeat
	// on its PENDING entry. Only first sightings, denied hooks and host
	// status events go on.
	if res := evt.PolicyResult; res != nil && !res.Disposition.Kept() {
		s.dropped.Add(1)
		if err := s.sendEventAck(stream, evt.ID, true); err != nil {
			return fmt.Errorf("send ack: %w", err)
		}
		return nil
	}

	// Persist the event.
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
	s.Publish(evt)

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

// handleHeartbeat updates the in-memory host tracker and records the
// heartbeat and its sensor snapshot in the store. The time recorded is the
// server's receive time: the bus's own timestamp could hold a host "online"
// past the watchdog timeout if its clock ran ahead. If the watchdog had
// marked the host UNRESPONSIVE, it raises AGENT_RECOVERED.
func (s *IngestionServer) handleHeartbeat(ctx context.Context, id *streamIdentity, hb *hookmonv1.Heartbeat) {
	hostID := s.resolve(id, hb.HostId, "heartbeat")
	if hostID == "" {
		s.logger.Warn("received heartbeat with empty host_id")
		return
	}

	now := s.now().UTC()

	// Update in-memory tracker. A heartbeat clears any shutdown announcement.
	s.hostMu.Lock()
	prev := s.hostTracker[hostID]
	st := &hostState{
		lastHeartbeat: now,
		agentVersion:  hb.AgentVersion,
	}
	if prev != nil {
		st.lastMarker = prev.lastMarker
	}
	s.hostTracker[hostID] = st
	s.hostMu.Unlock()

	// Persist heartbeat to the store.
	if s.store != nil {
		rec := &event.HostHeartbeat{
			HostID:        hostID,
			ReceivedAt:    now,
			AgentVersion:  hb.AgentVersion,
			KernelRelease: hb.KernelRelease,
			Sensors:       protoToSensors(hb.Sensors),
		}
		if recorder, ok := s.store.(HeartbeatRecorder); ok {
			change, err := recorder.RecordHeartbeat(ctx, rec)
			if err != nil {
				s.logger.Error("failed to update host heartbeat",
					zap.String("host_id", hostID),
					zap.Error(err),
				)
			} else if change.PrevStatus == event.HostUnresponsive || change.PrevStatus == event.HostOffline {
				s.hostRecovered(ctx, id, hostID, change, now)
			}
		} else if err := s.store.UpdateHostHeartbeat(ctx, rec); err != nil {
			s.logger.Error("failed to update host heartbeat",
				zap.String("host_id", hostID),
				zap.Error(err),
			)
		}
	}

	s.logger.Debug("heartbeat received",
		zap.String("host_id", hostID),
		zap.String("agent_version", hb.AgentVersion),
		zap.Uint64("events_sent", hb.EventsSent),
		zap.Int("sensors", len(hb.Sensors)),
	)
}

// hostRecovered raises AGENT_RECOVERED for a host whose heartbeat has just
// set it back ONLINE: it stores the event, sends it to every connector
// (StatusSink) and to the WebSocket feed, as the watchdog does with
// AGENT_OFFLINE. The heartbeat's single UPDATE reads the previous status,
// so each outage the watchdog recorded gets exactly one recovery.
func (s *IngestionServer) hostRecovered(ctx context.Context, id *streamIdentity, hostID string, change HeartbeatChange, now time.Time) {
	hostname := id.hostname
	if hostname == "" {
		if lookup, ok := s.store.(HostLookup); ok {
			if h, err := lookup.GetHost(ctx, hostID); err == nil && h != nil {
				hostname = h.Hostname
			}
		}
	}
	reason := fmt.Sprintf("Heartbeats resumed; the host was %s", change.PrevStatus)
	if !change.PrevHeartbeat.IsZero() {
		gap := now.Sub(change.PrevHeartbeat).Round(time.Second)
		reason = fmt.Sprintf("Heartbeats resumed after %s without one (last at %s); the host was %s, and events from that time may be missing",
			gap, change.PrevHeartbeat.UTC().Format(time.RFC3339), change.PrevStatus)
	}
	evt := &event.HookEvent{
		ID:        uuid.New().String(),
		Timestamp: now,
		HostID:    hostID,
		Hostname:  hostname,
		EventType: event.EventAgentRecovered,
		Severity:  event.SeverityInfo,
		PolicyResult: &event.PolicyResult{
			Action: event.ActionAlert,
			Reason: reason,
		},
	}
	s.logger.Info("host heartbeating again — generating AGENT_RECOVERED",
		zap.String("host_id", hostID),
		zap.String("hostname", hostname),
		zap.String("previous_status", string(change.PrevStatus)),
		zap.Time("previous_heartbeat", change.PrevHeartbeat),
	)
	if err := s.store.InsertEvent(ctx, evt); err != nil {
		s.logger.Error("failed to store AGENT_RECOVERED event", zap.String("host_id", hostID), zap.Error(err))
	}
	if s.statusSink != nil {
		s.statusSink.Dispatch(evt)
	}
	s.Publish(evt)
}

func (s *IngestionServer) handleShutdown(_ context.Context, id *streamIdentity, sd *hookmonv1.ShutdownNotice) {
	hostID := id.hostID
	if hostID == "" {
		return
	}
	now := s.now().UTC()
	s.hostMu.Lock()
	st, ok := s.hostTracker[hostID]
	if !ok {
		st = &hostState{}
		s.hostTracker[hostID] = st
	}
	st.shutdownReason = sd.GetReason()
	st.shutdownAt = now
	s.hostMu.Unlock()

	s.logger.Info("host announced shutdown",
		zap.String("host_id", hostID),
		zap.String("reason", sd.GetReason()),
	)
}

func (s *IngestionServer) handleMarker(id *streamIdentity) {
	hostID := id.hostID
	if hostID == "" {
		return
	}
	now := s.now().UTC()
	s.hostMu.Lock()
	st, ok := s.hostTracker[hostID]
	if !ok {
		st = &hostState{}
		s.hostTracker[hostID] = st
	}
	st.lastMarker = now
	s.hostMu.Unlock()
}

// HostShutdownAnnounced returns true if the host announced a clean shutdown
// and has not heartbeated since.
func (s *IngestionServer) HostShutdownAnnounced(hostID string) bool {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	st := s.hostTracker[hostID]
	return st != nil && st.shutdownReason != ""
}

// LastMarker returns the time of the last end-to-end marker from a host, or zero.
func (s *IngestionServer) LastMarker(hostID string) time.Time {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	st := s.hostTracker[hostID]
	if st == nil {
		return time.Time{}
	}
	return st.lastMarker
}

// WedgedHosts returns the IDs of hosts that have sent at least one marker
// but whose last marker is older than the given threshold, and that have
// not announced a shutdown.
func (s *IngestionServer) WedgedHosts(threshold time.Duration) []string {
	s.hostMu.RLock()
	defer s.hostMu.RUnlock()
	cutoff := time.Now().Add(-threshold)
	var out []string
	for id, st := range s.hostTracker {
		if st.lastMarker.IsZero() || st.shutdownReason != "" {
			continue
		}
		if st.lastMarker.Before(cutoff) {
			out = append(out, id)
		}
	}
	return out
}

// protoToSensors converts a heartbeat's sensor snapshot. Nil entries are
// skipped.
func protoToSensors(in []*hookmonv1.SensorHealth) []event.SensorHealth {
	if len(in) == 0 {
		return nil
	}
	out := make([]event.SensorHealth, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		out = append(out, event.SensorHealth{Name: s.Name, Status: s.Status, Reason: s.Reason})
	}
	return out
}

// sendEventAck sends an EventAck message back to the agent over the stream.
func (s *IngestionServer) sendEventAck(stream hookmonv1.AgentService_StreamEventsServer, eventID string, accepted bool) error {
	return stream.Send(&hookmonv1.ServerMessage{
		Payload: &hookmonv1.ServerMessage_Ack{Ack: &hookmonv1.EventAck{
			EventId:  eventID,
			Accepted: accepted,
		}},
	})
}

// Enroll is not served on the mutual-TLS listener: a bus that needs to
// enroll has no client certificate to reach it with. See Enroller.
func (s *IngestionServer) Enroll(context.Context, *hookmonv1.EnrollRequest) (*hookmonv1.EnrollResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Enroll is served on the enrollment listener, not here")
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
	hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION:  event.EventExecInjection,
	hookmonv1.EventType_EVENT_TYPE_SHM_CREATE:      event.EventSHMCreate,
	hookmonv1.EventType_EVENT_TYPE_DLOPEN:          event.EventDlopen,
	hookmonv1.EventType_EVENT_TYPE_LINKER_CONFIG:   event.EventLinkerConfig,
	hookmonv1.EventType_EVENT_TYPE_PTRACE_INJECT:   event.EventPtraceInject,
	hookmonv1.EventType_EVENT_TYPE_LIB_INTEGRITY:   event.EventLibIntegrity,
	hookmonv1.EventType_EVENT_TYPE_AGENT_OFFLINE:   event.EventAgentOffline,
	hookmonv1.EventType_EVENT_TYPE_AGENT_RECOVERED: event.EventAgentRecovered,
	hookmonv1.EventType_EVENT_TYPE_ELF_RPATH:       event.EventElfRpath,
	hookmonv1.EventType_EVENT_TYPE_BPF_INVENTORY:   event.EventBPFInventory,
}

// protoToEvent converts a proto HookEvent to the canonical event.HookEvent
// used by the server's domain layer (store, policy engine, connectors).
func protoToEvent(pe *hookmonv1.HookEvent) *event.HookEvent {
	if pe == nil {
		return nil
	}

	evt := &event.HookEvent{
		ID:          pe.Id,
		HostID:      pe.HostId,
		Hostname:    pe.Hostname,
		PID:         pe.Pid,
		PPID:        pe.Ppid,
		UID:         pe.Uid,
		GID:         pe.Gid,
		Comm:        pe.Comm,
		Cmdline:     pe.Cmdline,
		ExePath:     pe.ExePath,
		ExeHash:     pe.ExeHash,
		CgroupPath:  pe.CgroupPath,
		ContainerID: pe.ContainerId,
		Namespace:   pe.Namespace,
	}

	// A nil proto timestamp leaves evt.Timestamp zero so validation rejects it.
	if pe.Timestamp != nil {
		evt.Timestamp = pe.Timestamp.AsTime()
	}

	// Map proto enum to domain string type. UNSPECIFIED (the zero value, a
	// message without a type) stays empty so validation reports it missing;
	// a value this server does not know keeps its name, and validation
	// refuses it.
	if mapped, ok := protoEventTypeToEventType[pe.EventType]; ok {
		evt.EventType = mapped
	} else if pe.EventType != hookmonv1.EventType_EVENT_TYPE_UNSPECIFIED {
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
		// Left empty, not INFO: the policy engine treats a bus INFO rating as
		// deliberate and never raises it, but rates an event that came
		// without one itself (reportedSeverity).
		evt.Severity = ""
	}

	// Convert type-specific detail payloads.
	if pe.BpfDetail != nil {
		evt.BPFDetail = &event.BPFDetail{
			BPFCommand:   pe.BpfDetail.BpfCmd,
			ProgType:     pe.BpfDetail.ProgType,
			ProgName:     pe.BpfDetail.ProgName,
			AttachType:   pe.BpfDetail.AttachType,
			TargetFD:     pe.BpfDetail.TargetFd,
			InsnCount:    pe.BpfDetail.InsnCount,
			ProgHash:     pe.BpfDetail.ProgHash,
			ProgID:       pe.BpfDetail.ProgId,
			AttachTarget: pe.BpfDetail.AttachTarget,
		}
		if pe.BpfDetail.LoadTime != nil {
			t := pe.BpfDetail.LoadTime.AsTime()
			evt.BPFDetail.LoadTime = &t
		}
		if pe.BpfDetail.CreatedByUid != nil {
			uid := pe.BpfDetail.GetCreatedByUid()
			evt.BPFDetail.CreatedByUID = &uid
		}
	}
	if pe.BpfInventoryDetail != nil {
		evt.BPFInventoryDetail = &event.BPFInventoryDetail{
			ScanID:    pe.BpfInventoryDetail.ScanId,
			Summary:   pe.BpfInventoryDetail.Summary,
			ProgCount: pe.BpfInventoryDetail.ProgCount,
			ByType:    pe.BpfInventoryDetail.ByType,
		}
	}
	if pe.ExecInjectionDetail != nil {
		evt.ExecInjectionDetail = &event.ExecInjectionDetail{
			LibraryPath:    pe.ExecInjectionDetail.LibraryPath,
			LibraryHash:    pe.ExecInjectionDetail.LibraryHash,
			TargetBinary:   pe.ExecInjectionDetail.TargetBinary,
			SetBy:          pe.ExecInjectionDetail.SetBy,
			EnvVar:         pe.ExecInjectionDetail.EnvVar,
			ScanTruncated:  pe.ExecInjectionDetail.ScanTruncated,
			ValueTruncated: pe.ExecInjectionDetail.ValueTruncated,
		}
	}
	if pe.ShmDetail != nil {
		evt.SHMDetail = &event.SHMDetail{
			SHMName: pe.ShmDetail.ShmName,
			Size:    pe.ShmDetail.Size,
			Pattern: pe.ShmDetail.Pattern,
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
			TargetPID:   pe.PtraceDetail.TargetPid,
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
	if pe.ElfRpathDetail != nil {
		// Entries never arrive nil off the wire, but a nil element must
		// not stop the server if one ever reaches here; it is skipped.
		entries := make([]event.RpathEntry, 0, len(pe.ElfRpathDetail.Entries))
		for _, e := range pe.ElfRpathDetail.Entries {
			if e == nil {
				continue
			}
			entries = append(entries, event.RpathEntry{
				Path:    e.Path,
				Risk:    event.RpathRisk(e.Risk),
				Reason:  e.Reason,
				Exists:  e.Exists,
				IsRpath: e.IsRpath,
			})
		}
		evt.ElfRpathDetail = &event.ElfRpathDetail{
			HasRpath:       pe.ElfRpathDetail.HasRpath,
			HasRunpath:     pe.ElfRpathDetail.HasRunpath,
			RpathRaw:       pe.ElfRpathDetail.RpathRaw,
			RunpathRaw:     pe.ElfRpathDetail.RunpathRaw,
			Entries:        entries,
			HighestRisk:    event.RpathRisk(pe.ElfRpathDetail.HighestRisk),
			UsesOrigin:     pe.ElfRpathDetail.UsesOrigin,
			UsesDeprecated: pe.ElfRpathDetail.UsesDeprecated,
			IsSetuid:       pe.ElfRpathDetail.IsSetuid,
		}
	}

	return evt
}
