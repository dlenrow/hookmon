package ingestion

// Tests for fix plan step 7f: the recovery interceptors, hostile protos,
// nil list elements, the bounded rate limiter keyed by certificate,
// AGENT_RECOVERED, refusing bus-sent host status events, the enrolled
// hostname, and counted feed drops.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// robServe serves svc over bufconn as server.Run does: TLS with clientAuth,
// and the recovery interceptors.
func robServe(t *testing.T, pki *enrpki.PKI, svc hookmonv1.AgentServiceServer, clientAuth tls.ClientAuthType) *enrWire {
	t.Helper()
	lis := bufconn.Listen(16 << 20)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(pki.ServerTLS(t, clientAuth))),
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(zap.NewNop())),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(zap.NewNop())),
	)
	hookmonv1.RegisterAgentServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return &enrWire{pki: pki, lis: lis}
}

// robPanicStore panics where a bug would: storing the event with ID
// "rob-panic", or enrolling the hostname "rob-panic".
type robPanicStore struct {
	*memStore
}

func (s robPanicStore) InsertEvent(ctx context.Context, evt *event.HookEvent) error {
	if evt.ID == "rob-panic" {
		var d *event.ElfRpathDetail
		_ = d.Entries[0] // nil pointer dereference, as before the 7f nil checks
	}
	return s.memStore.InsertEvent(ctx, evt)
}

func (s robPanicStore) EnrollHost(ctx context.Context, h *event.Host, name, fp string) error {
	if h.Hostname == "rob-panic" {
		panic("rob: enrollment bug")
	}
	return s.memStore.EnrollHost(ctx, h, name, fp)
}

// robEvent is a valid BPF_LOAD event.
func robEvent(id string) *hookmonv1.HookEvent {
	return &hookmonv1.HookEvent{
		Id: id, Timestamp: timestamppb.Now(), HostId: "claimed", Hostname: "claimed",
		EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD, Severity: hookmonv1.Severity_SEVERITY_WARN,
	}
}

func robEventMsg(e *hookmonv1.HookEvent) *hookmonv1.AgentMessage {
	return &hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: e}}
}

// robAck sends one event on a new stream and returns its ack, or the
// stream's error.
func robAck(t *testing.T, client hookmonv1.AgentServiceClient, e *hookmonv1.HookEvent) (*hookmonv1.EventAck, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(robEventMsg(e)); err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	_ = stream.CloseSend()
	return resp.GetAck(), nil
}

// TestRobustness_StreamPanicKeepsServing: a panic in the stream handler
// (here, in the store) ends that stream with codes.Internal. The server
// keeps serving: a new stream from the same host, and one from another
// host, are accepted. Without the interceptor the panic would stop the
// process, and this test binary with it.
func TestRobustness_StreamPanicKeepsServing(t *testing.T) {
	store := robPanicStore{newMemStore()}
	pki := enrpki.New(t)
	w := robServe(t, pki, NewIngestionServer(IngestionConfig{Store: store}), tls.RequireAndVerifyClientCert)
	client := w.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false)

	_, err := robAck(t, client, robEvent("rob-panic"))
	if status.Code(err) != codes.Internal {
		t.Fatalf("stream whose handler panicked: got %v, want Internal", err)
	}
	if strings.Contains(err.Error(), "nil pointer") {
		t.Errorf("the panic value reached the client: %v", err)
	}

	for name, c := range map[string]hookmonv1.AgentServiceClient{
		"same host":    client,
		"another host": w.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false),
	} {
		ack, err := robAck(t, c, robEvent("after-"+strings.ReplaceAll(name, " ", "-")))
		if err != nil || !ack.GetAccepted() {
			t.Errorf("%s after the panic: ack %v, err %v; want accepted", name, ack, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 2 {
		t.Errorf("stored %d events after the panic, want 2", len(store.events))
	}
}

// TestRobustness_EnrollPanicKeepsServing: the same for the unary Enroll RPC
// on the enrollment listener.
func TestRobustness_EnrollPanicKeepsServing(t *testing.T) {
	store := robPanicStore{newMemStore()}
	pki := enrpki.New(t)
	ca, err := hcrypto.ParseCA(pki.CACertPEM, pki.CAKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	secret := "rob-0123456789abcdef0123456789abcdef"
	tokens, err := hcrypto.NewTokenSet([]hcrypto.EnrollmentToken{{Name: "rob", Secret: secret, Expires: time.Now().Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	w := robServe(t, pki, NewEnroller(EnrollerConfig{Store: store, Tokens: tokens, CA: ca}), tls.NoClientCert)
	client := w.enrDial(t, nil, false)
	_, csr, err := hcrypto.GenerateAgentKeypair("x")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Enroll(ctx, &hookmonv1.EnrollRequest{EnrollmentToken: secret, Hostname: "rob-panic", Csr: csr})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Enroll whose handler panicked: got %v, want Internal", err)
	}
	resp, err := client.Enroll(ctx, &hookmonv1.EnrollRequest{EnrollmentToken: secret, Hostname: "web-ok", Csr: csr})
	if err != nil || resp.GetHostId() == "" {
		t.Fatalf("Enroll after the panic: %v, %v", resp, err)
	}
}

// TestRobustness_HostileProtos sends what a broken or hostile bus could put
// on the wire: a message with no payload, a set oneof with an empty event,
// RPATH entries that are empty messages, enum values out of range, an event
// with no type, strings of 768 KiB in four fields, and a message over the 4 MiB
// limit. Each gets a negative ack, is stored, or ends its stream with
// ResourceExhausted; nothing stops the server, and a normal event is
// accepted afterwards on the same connection.
func TestRobustness_HostileProtos(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	ing := NewIngestionServer(IngestionConfig{Store: store, RateLimiter: NewRateLimiter(1000, 1000)})
	w := robServe(t, pki, ing, tls.RequireAndVerifyClientCert)
	hostID := uuid.New().String()
	client := w.enrDial(t, enrHostCert(t, pki, hostID), false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}

	big := strings.Repeat("A", 768<<10) // four of these fit in one 4 MiB message
	huge := robEvent("rob-huge")
	huge.Hostname, huge.Comm, huge.Cmdline, huge.ExePath = big, big, big, "/"+big
	emptyEntries := robEvent("rob-empty-entries")
	emptyEntries.EventType = hookmonv1.EventType_EVENT_TYPE_ELF_RPATH
	emptyEntries.ElfRpathDetail = &hookmonv1.ElfRpathDetail{
		Entries: []*hookmonv1.RpathEntry{{}, {Path: "/tmp/x", Risk: "CRITICAL"}, {}},
	}
	badType := robEvent("rob-bad-type")
	badType.EventType = hookmonv1.EventType(1 << 20)
	badSeverity := robEvent("rob-bad-severity")
	badSeverity.Severity = hookmonv1.Severity(-7)
	emptyDetails := robEvent("rob-empty-details")
	emptyDetails.BpfDetail, emptyDetails.ExecInjectionDetail = &hookmonv1.BPFDetail{}, &hookmonv1.ExecInjectionDetail{}
	emptyDetails.ShmDetail, emptyDetails.DlopenDetail = &hookmonv1.SHMDetail{}, &hookmonv1.DlopenDetail{}
	emptyDetails.LinkerConfigDetail, emptyDetails.PtraceDetail = &hookmonv1.LinkerConfigDetail{}, &hookmonv1.PtraceDetail{}
	emptyDetails.LibIntegrityDetail, emptyDetails.BpfInventoryDetail = &hookmonv1.LibIntegrityDetail{}, &hookmonv1.BPFInventoryDetail{}

	type want struct {
		id       string
		accepted bool
	}
	msgs := []struct {
		msg  *hookmonv1.AgentMessage
		want *want // nil: no ack expected
	}{
		{&hookmonv1.AgentMessage{}, nil}, // empty oneof
		{&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
			Sensors: []*hookmonv1.SensorHealth{{}, {Name: big}}}}}, nil},
		{robEventMsg(&hookmonv1.HookEvent{}), &want{"", false}},                                       // oneof set, event empty
		{robEventMsg(huge), &want{"rob-huge", true}},                                                  // 768 KiB fields
		{robEventMsg(emptyEntries), &want{"rob-empty-entries", true}},                                 // empty RPATH entries
		{robEventMsg(badType), &want{"rob-bad-type", false}},                                          // unknown event type
		{robEventMsg(badSeverity), &want{"rob-bad-severity", true}},                                   // unknown severity: the engine rates it
		{robEventMsg(emptyDetails), &want{"rob-empty-details", true}},                                 // every detail empty
		{robEventMsg(&hookmonv1.HookEvent{Id: big, Timestamp: timestamppb.Now()}), &want{big, false}}, // no type
	}
	for _, m := range msgs {
		if err := stream.Send(m.msg); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	for _, m := range msgs {
		if m.want == nil {
			continue
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv ack for %.20q: %v", m.want.id, err)
		}
		if ack := resp.GetAck(); ack.GetEventId() != m.want.id || ack.GetAccepted() != m.want.accepted {
			t.Errorf("ack (%.20q, %v), want (%.20q, %v)", ack.GetEventId(), ack.GetAccepted(), m.want.id, m.want.accepted)
		}
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("end of stream: %v", err)
	}

	store.mu.Lock()
	byID := map[string]*event.HookEvent{}
	for _, e := range store.events {
		byID[e.ID] = e
	}
	store.mu.Unlock()
	if e := byID["rob-empty-entries"]; e == nil || len(e.ElfRpathDetail.Entries) != 3 || e.ElfRpathDetail.Entries[1].Path != "/tmp/x" {
		t.Errorf("RPATH event with empty entries: %+v", e)
	}
	if e := byID["rob-huge"]; e == nil || len(e.Cmdline) != len(big) || e.HostID != hostID || e.Hostname != "" {
		t.Errorf("768 KiB event: stored %v; host %q, hostname %.20q (the host is not enrolled, so none)", e != nil, e.HostID, e.Hostname)
	}

	// Over the server's 4 MiB message limit: that stream fails, the
	// connection and the server do not.
	tooBig := robEvent("rob-too-big")
	tooBig.Cmdline = strings.Repeat("B", 5<<20)
	if _, err := robAck(t, client, tooBig); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("5 MiB message: got %v, want ResourceExhausted", err)
	}
	if ack, err := robAck(t, client, robEvent("rob-after")); err != nil || !ack.GetAccepted() {
		t.Errorf("normal event after the hostile ones: ack %v, err %v", ack, err)
	}
}

// robFakeStream is an in-process StreamEvents stream. Messages built in
// process can hold what the wire never delivers, such as nil list
// elements.
type robFakeStream struct {
	grpc.ServerStream
	ctx  context.Context
	in   []*hookmonv1.AgentMessage
	mu   sync.Mutex
	acks []*hookmonv1.EventAck
}

func (s *robFakeStream) Context() context.Context { return s.ctx }
func (s *robFakeStream) Recv() (*hookmonv1.AgentMessage, error) {
	if len(s.in) == 0 {
		return nil, io.EOF
	}
	m := s.in[0]
	s.in = s.in[1:]
	return m, nil
}
func (s *robFakeStream) Send(m *hookmonv1.ServerMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks = append(s.acks, m.GetAck())
	return nil
}
func (s *robFakeStream) SetHeader(metadata.MD) error  { return nil }
func (s *robFakeStream) SendHeader(metadata.MD) error { return nil }
func (s *robFakeStream) SetTrailer(metadata.MD)       {}

// TestRobustness_NilListElements: nil RPATH entries and nil sensor entries
// are skipped by the converters, through the real handler. Before step 7f
// a nil RPATH entry was dereferenced.
func TestRobustness_NilListElements(t *testing.T) {
	pe := robEvent("rob-nil-entries")
	pe.HostId = "dev-host"
	pe.EventType = hookmonv1.EventType_EVENT_TYPE_ELF_RPATH
	pe.ElfRpathDetail = &hookmonv1.ElfRpathDetail{
		HighestRisk: "CRITICAL",
		Entries:     []*hookmonv1.RpathEntry{nil, {Path: "/tmp/evil", Risk: "CRITICAL"}, nil},
	}
	if got := protoToEvent(pe).ElfRpathDetail.Entries; len(got) != 1 || got[0].Path != "/tmp/evil" {
		t.Errorf("protoToEvent entries: %+v", got)
	}
	if got := protoToSensors([]*hookmonv1.SensorHealth{nil, {Name: "bpf_syscall", Status: "alive"}, nil}); len(got) != 1 {
		t.Errorf("protoToSensors: %+v", got)
	}

	store := newMemStore()
	ing := NewIngestionServer(IngestionConfig{Store: store, Insecure: true})
	stream := &robFakeStream{ctx: context.Background(), in: []*hookmonv1.AgentMessage{
		robEventMsg(pe),
		{Payload: &hookmonv1.AgentMessage_Event{Event: nil}},
		{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
			HostId: "dev-host", Sensors: []*hookmonv1.SensorHealth{nil, {Name: "bpf_syscall", Status: "alive"}},
		}}},
	}}
	if err := RecoveryStreamInterceptor(zap.NewNop())(ing, stream, &grpc.StreamServerInfo{FullMethod: "test"},
		func(srv any, ss grpc.ServerStream) error {
			return srv.(*IngestionServer).StreamEvents(ss.(*robFakeStream))
		}); err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	if len(stream.acks) != 1 || !stream.acks[0].GetAccepted() {
		t.Errorf("acks: %+v", stream.acks)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 1 || len(store.events[0].ElfRpathDetail.Entries) != 1 {
		t.Errorf("stored: %+v", store.events)
	}
	if hb := store.heartbeats["dev-host"]; hb == nil || len(hb.Sensors) != 1 {
		t.Errorf("heartbeat: %+v", hb)
	}
}

// TestRateLimiter_Bounded: many distinct hosts never grow the table past
// its bound, and the host seen least recently is the one evicted.
func TestRateLimiter_Bounded(t *testing.T) {
	rl := NewRateLimiterSize(1, 1, 64)
	for i := 0; i < 100000; i++ {
		rl.Allow(fmt.Sprintf("host-%d", i))
		if rl.Len() > 64 {
			t.Fatalf("after %d hosts the table holds %d, bound 64", i+1, rl.Len())
		}
	}
	if rl.Len() != 64 {
		t.Errorf("table holds %d, want 64", rl.Len())
	}

	// LRU: a host that keeps sending keeps its (empty) bucket while others
	// come and go; one that stops is evicted and starts with a full one.
	rl = NewRateLimiterSize(0, 1, 4) // rate 0: a bucket never refills
	if !rl.Allow("busy") || rl.Allow("busy") {
		t.Fatal("burst of 1 not enforced")
	}
	for i := 0; i < 20; i++ {
		rl.Allow(fmt.Sprintf("churn-%d", i))
		if rl.Allow("busy") {
			t.Fatalf("busy host's limit was reset by churn (round %d)", i)
		}
	}
	for i := 0; i < 4; i++ {
		rl.Allow(fmt.Sprintf("more-%d", i))
	}
	if !rl.Allow("busy") {
		t.Error("a host evicted by 4 newer hosts should start with a full bucket")
	}
}

// TestRateLimiter_KeyedByCertificate: the limit follows the certificate,
// not the host ID in the message. One host naming many others is limited
// as one host, and many hosts (each its own certificate) keep the table
// within its bound.
func TestRateLimiter_KeyedByCertificate(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	rl := NewRateLimiterSize(0, 3, 8) // 3 events per host, ever; at most 8 hosts kept
	w := robServe(t, pki, NewIngestionServer(IngestionConfig{Store: store, RateLimiter: rl}), tls.RequireAndVerifyClientCert)

	client := w.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		e := robEvent(fmt.Sprintf("spray-%d", i))
		e.HostId = uuid.New().String() // a different host in every message
		if err := stream.Send(robEventMsg(e)); err != nil {
			t.Fatal(err)
		}
	}
	accepted := 0
	for i := 0; i < 6; i++ {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetAck().GetAccepted() {
			accepted++
		}
	}
	_ = stream.CloseSend()
	if accepted != 3 {
		t.Errorf("one certificate naming 6 hosts: %d accepted, want 3 (its own limit)", accepted)
	}

	const hosts = 40
	for i := 0; i < hosts; i++ {
		c := w.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false)
		if ack, err := robAck(t, c, robEvent(fmt.Sprintf("host-%d", i))); err != nil || !ack.GetAccepted() {
			t.Fatalf("host %d: %v %v", i, ack, err)
		}
		if rl.Len() > 8 {
			t.Fatalf("after %d certificates the limiter holds %d hosts, bound 8", i+1, rl.Len())
		}
	}
	if rl.Len() != 8 {
		t.Errorf("limiter holds %d hosts, want 8", rl.Len())
	}
}

// robStatusStore is a Store that records heartbeats with their previous
// status (HeartbeatRecorder) and looks hosts up (HostLookup).
type robStatusStore struct {
	*memStore
	status map[string]event.HostStatus
	last   map[string]time.Time
}

func newRobStatusStore() *robStatusStore {
	return &robStatusStore{memStore: newMemStore(), status: map[string]event.HostStatus{}, last: map[string]time.Time{}}
}

func (s *robStatusStore) RecordHeartbeat(_ context.Context, hb *event.HostHeartbeat) (HeartbeatChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.status[hb.HostID]
	if !ok {
		return HeartbeatChange{}, fmt.Errorf("host %s is not enrolled", hb.HostID)
	}
	c := HeartbeatChange{PrevStatus: prev, PrevHeartbeat: s.last[hb.HostID]}
	s.status[hb.HostID], s.last[hb.HostID] = event.HostOnline, hb.ReceivedAt
	s.heartbeats[hb.HostID] = hb
	return c, nil
}

func (s *robStatusStore) eventsOfType(et event.EventType) []*event.HookEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*event.HookEvent
	for _, e := range s.events {
		if e.EventType == et {
			out = append(out, e)
		}
	}
	return out
}

// robSink records what is dispatched to it.
type robSink struct {
	mu   sync.Mutex
	evts []*event.HookEvent
}

func (s *robSink) Dispatch(evt *event.HookEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evts = append(s.evts, evt)
}

func robHeartbeat(t *testing.T, client hookmonv1.AgentServiceClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{AgentVersion: "v"}}}); err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("end of stream: %v", err)
	}
}

// TestRecovered_OnHeartbeatAfterUnresponsive: the first heartbeat from a
// host the watchdog marked UNRESPONSIVE raises one AGENT_RECOVERED, named
// with the enrolled hostname, stored, dispatched to the connectors and
// published to the WebSocket feed. A host that was ONLINE raises none,
// and neither does the next heartbeat.
func TestRecovered_OnHeartbeatAfterUnresponsive(t *testing.T) {
	store := newRobStatusStore()
	sink := &robSink{}
	pki := enrpki.New(t)
	ing := NewIngestionServer(IngestionConfig{Store: store, StatusSink: sink})
	w := robServe(t, pki, ing, tls.RequireAndVerifyClientCert)

	down, up := uuid.New().String(), uuid.New().String()
	lastBeat := time.Now().UTC().Add(-3 * time.Minute)
	store.hosts = append(store.hosts, &event.Host{ID: down, Hostname: "web-down"}, &event.Host{ID: up, Hostname: "web-up"})
	store.status[down], store.last[down] = event.HostUnresponsive, lastBeat
	store.status[up], store.last[up] = event.HostOnline, time.Now().UTC()

	robHeartbeat(t, w.enrDial(t, enrHostCert(t, pki, up), false))
	downClient := w.enrDial(t, enrHostCert(t, pki, down), false)
	robHeartbeat(t, downClient)
	robHeartbeat(t, downClient)

	rec := store.eventsOfType(event.EventAgentRecovered)
	if len(rec) != 1 {
		t.Fatalf("AGENT_RECOVERED stored: %d, want 1", len(rec))
	}
	e := rec[0]
	if e.HostID != down || e.Hostname != "web-down" || e.Severity != event.SeverityInfo ||
		e.PolicyResult == nil || e.PolicyResult.Action != event.ActionAlert ||
		!strings.Contains(e.PolicyResult.Reason, "UNRESPONSIVE") || !strings.Contains(e.PolicyResult.Reason, "3m") {
		t.Errorf("AGENT_RECOVERED: %+v %+v", e, e.PolicyResult)
	}
	sink.mu.Lock()
	if len(sink.evts) != 1 || sink.evts[0] != e {
		t.Errorf("dispatched to the connectors: %+v", sink.evts)
	}
	sink.mu.Unlock()
	select {
	case got := <-ing.GetEventChannel():
		if got != e {
			t.Errorf("published %+v, want the AGENT_RECOVERED", got)
		}
	default:
		t.Error("AGENT_RECOVERED was not published to the WebSocket feed")
	}
}

// TestStatusEventsFromBusRefused: AGENT_OFFLINE and AGENT_RECOVERED are
// raised only by the server. On a bus's stream they get a negative ack and
// are not stored, so each has one source and one severity.
func TestStatusEventsFromBusRefused(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	w := robServe(t, pki, NewIngestionServer(IngestionConfig{Store: store}), tls.RequireAndVerifyClientCert)
	client := w.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false)
	for _, et := range []hookmonv1.EventType{hookmonv1.EventType_EVENT_TYPE_AGENT_OFFLINE, hookmonv1.EventType_EVENT_TYPE_AGENT_RECOVERED} {
		e := robEvent("bus-" + et.String())
		e.EventType = et
		ack, err := robAck(t, client, e)
		if err != nil || ack.GetAccepted() {
			t.Errorf("%s from a bus: ack %v, err %v; want a negative ack", et, ack, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 0 {
		t.Errorf("stored %d bus-sent status events", len(store.events))
	}
}

// TestHostname_FromEnrollment: events are stored with the hostname the
// host enrolled with, whatever the message says; the mismatch is logged
// once per stream.
func TestHostname_FromEnrollment(t *testing.T) {
	store := newMemStore()
	core, logs := observer.New(zapcore.WarnLevel)
	pki := enrpki.New(t)
	w := robServe(t, pki, NewIngestionServer(IngestionConfig{Store: store, Logger: zap.New(core)}), tls.RequireAndVerifyClientCert)
	hostID := uuid.New().String()
	store.hosts = append(store.hosts, &event.Host{ID: hostID, Hostname: "db-enrolled"})
	client := w.enrDial(t, enrHostCert(t, pki, hostID), false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e := robEvent(fmt.Sprintf("hn-%d", i))
		e.Hostname = "pretends-to-be-the-dc"
		if err := stream.Send(robEventMsg(e)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	_ = stream.CloseSend()
	store.mu.Lock()
	for _, e := range store.events {
		if e.Hostname != "db-enrolled" {
			t.Errorf("event %s stored with hostname %q, want the enrolled db-enrolled", e.ID, e.Hostname)
		}
	}
	store.mu.Unlock()
	if n := logs.FilterMessageSnippet("different hostname").Len(); n != 1 {
		t.Errorf("hostname mismatch warnings: %d, want 1 per stream", n)
	}
}

// TestPublish_DropsCountedAndLogged: when the WebSocket feed's buffer is
// full, Publish drops, counts, and warns at most once per 10 s, with the
// number dropped since the last warning.
func TestPublish_DropsCountedAndLogged(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ing := NewIngestionServer(IngestionConfig{Logger: zap.New(core), EventChannelSize: 2, Now: func() time.Time { return now }})

	for i := 0; i < 7; i++ {
		ing.Publish(&event.HookEvent{ID: fmt.Sprintf("e%d", i)})
	}
	if got := ing.BroadcastDrops(); got != 5 {
		t.Errorf("drops: %d, want 5", got)
	}
	if n := logs.Len(); n != 1 {
		t.Fatalf("warnings: %d, want 1", n)
	}
	now = now.Add(11 * time.Second)
	ing.Publish(&event.HookEvent{ID: "later"})
	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("warnings after 11 s: %d, want 2", len(entries))
	}
	f := entries[1].ContextMap()
	if f["dropped_since_last_warning"] != uint64(5) || f["dropped_total"] != uint64(6) {
		t.Errorf("second warning fields: %v", f)
	}
	if len(ing.GetEventChannel()) != 2 {
		t.Errorf("buffer holds %d, want the first 2 events", len(ing.GetEventChannel()))
	}
}
