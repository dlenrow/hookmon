package ingestion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// memStore is an in-memory Store and EnrollStore that records every call
// for assertions.
type memStore struct {
	mu         sync.Mutex
	events     []*event.HookEvent
	hosts      []*event.Host
	heartbeats map[string]*event.HostHeartbeat
	usedTokens map[string]string // fingerprint -> host ID
}

func newMemStore() *memStore {
	return &memStore{
		heartbeats: make(map[string]*event.HostHeartbeat),
		usedTokens: make(map[string]string),
	}
}

func (m *memStore) InsertEvent(_ context.Context, evt *event.HookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evt)
	return nil
}

func (m *memStore) EnrollHost(_ context.Context, host *event.Host, _, consumeFingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if consumeFingerprint != "" {
		if _, used := m.usedTokens[consumeFingerprint]; used {
			return hcrypto.ErrTokenUsed
		}
		m.usedTokens[consumeFingerprint] = host.ID
	}
	m.hosts = append(m.hosts, host)
	return nil
}

func (m *memStore) UpdateHostHeartbeat(_ context.Context, hb *event.HostHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeats[hb.HostID] = hb
	return nil
}

// GetHost returns an enrolled host (HostLookup), so the ingestion server
// can name a certificate's host by the hostname it enrolled with.
func (m *memStore) GetHost(_ context.Context, id string) (*event.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range m.hosts {
		if h.ID == id {
			c := *h
			return &c, nil
		}
	}
	return nil, fmt.Errorf("host %s is not enrolled", id)
}

// enrWire serves an AgentService implementation over an in-memory bufconn
// listener with real TLS, so the server sees real peer certificates.
type enrWire struct {
	pki *enrpki.PKI
	lis *bufconn.Listener
}

// enrServe serves svc over bufconn. clientAuth is the server's client
// certificate policy; tls.NoClientCert with plaintext false still uses TLS.
// plaintext serves without TLS at all.
func enrServe(t *testing.T, pki *enrpki.PKI, svc hookmonv1.AgentServiceServer, clientAuth tls.ClientAuthType, plaintext bool) *enrWire {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	var opts []grpc.ServerOption
	if !plaintext {
		opts = append(opts, grpc.Creds(credentials.NewTLS(pki.ServerTLS(t, clientAuth))))
	}
	srv := grpc.NewServer(opts...)
	hookmonv1.RegisterAgentServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return &enrWire{pki: pki, lis: lis}
}

// enrDial returns a client for w that presents cert (nil: none). plaintext
// dials without TLS.
func (w *enrWire) enrDial(t *testing.T, cert *tls.Certificate, plaintext bool) hookmonv1.AgentServiceClient {
	t.Helper()
	creds := insecure.NewCredentials()
	if !plaintext {
		creds = credentials.NewTLS(w.pki.ClientTLS(cert))
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return w.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return hookmonv1.NewAgentServiceClient(conn)
}

// enrHostCert issues a bus certificate for hostID, as enrollment would.
func enrHostCert(t *testing.T, pki *enrpki.PKI, hostID string) *tls.Certificate {
	t.Helper()
	c := pki.ClientCert(t, hostID, hcrypto.HostCertOrganization)
	return &c
}

// TestWire_StreamEvents sends events and a heartbeat over mutual TLS. The
// messages name host "host-1"; the server must record them under the host
// ID in the client certificate.
func TestWire_StreamEvents(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	ing := NewIngestionServer(IngestionConfig{Store: store})
	w := enrServe(t, pki, ing, tls.RequireAndVerifyClientCert, false)
	hostID := uuid.New().String()
	client := w.enrDial(t, enrHostCert(t, pki, hostID), false)
	// The host enrolled as "web-enrolled". The messages below say "web-01";
	// since step 7f the server records the enrolled name, not the bus's.
	store.hosts = append(store.hosts, &event.Host{ID: hostID, Hostname: "web-enrolled"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ts := time.Date(2025, 6, 15, 12, 0, 0, 123456789, time.UTC)
	hbTS := ts.Add(5 * time.Second)

	execEvt := &hookmonv1.HookEvent{
		Id:          "evt-exec-1",
		Timestamp:   timestamppb.New(ts),
		HostId:      "host-1",
		Hostname:    "web-01",
		EventType:   hookmonv1.EventType_EVENT_TYPE_EXEC_INJECTION,
		Severity:    hookmonv1.Severity_SEVERITY_ALERT,
		Pid:         4242,
		Ppid:        1,
		Uid:         1000,
		Gid:         1000,
		Comm:        "target",
		Cmdline:     "/usr/bin/target --flag",
		ExePath:     "/usr/bin/target",
		ExeHash:     "sha256:exe",
		CgroupPath:  "/sys/fs/cgroup/user.slice",
		ContainerId: "ctr-abc",
		Namespace:   "prod",
		ExecInjectionDetail: &hookmonv1.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	rpathEvt := &hookmonv1.HookEvent{
		Id:        "evt-rpath-1",
		Timestamp: timestamppb.New(ts),
		HostId:    "host-1",
		Hostname:  "web-01",
		EventType: hookmonv1.EventType_EVENT_TYPE_ELF_RPATH,
		Severity:  hookmonv1.Severity_SEVERITY_CRITICAL,
		Pid:       4243,
		ExePath:   "/opt/app/bin/app",
		ElfRpathDetail: &hookmonv1.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: true,
			RpathRaw:   "/tmp/evil:$ORIGIN/../lib",
			RunpathRaw: "/opt/app/lib",
			Entries: []*hookmonv1.RpathEntry{
				{Path: "/tmp/evil", Risk: "CRITICAL", Reason: "world-writable", Exists: true, IsRpath: true},
				{Path: "$ORIGIN/../lib", Risk: "LOW", Reason: "origin-relative", Exists: true, IsRpath: true},
				{Path: "/opt/app/lib", Risk: "MEDIUM", Reason: "non-standard", Exists: false, IsRpath: false},
			},
			HighestRisk:    "CRITICAL",
			UsesOrigin:     true,
			UsesDeprecated: true,
			IsSetuid:       true,
		},
	}
	// Missing timestamp, so the server must reject it with a negative ack.
	// (A missing host_id is no longer invalid: the server takes the host ID
	// from the certificate.)
	invalidEvt := &hookmonv1.HookEvent{
		Id:        "evt-invalid",
		HostId:    "host-1",
		EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
	}

	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	for _, pe := range []*hookmonv1.HookEvent{execEvt, rpathEvt, invalidEvt} {
		msg := &hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: pe}}
		if err := stream.Send(msg); err != nil {
			t.Fatalf("send event %s: %v", pe.Id, err)
		}
	}
	hb := &hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
		HostId:        "host-1",
		Timestamp:     timestamppb.New(hbTS),
		AgentVersion:  "1.2.3",
		EventsSent:    2,
		UptimeSeconds: 60,
		Sensors: []*hookmonv1.SensorHealth{
			{Name: "bpf_syscall", Status: "alive"},
			{Name: "dlopen_monitor", Status: "unverifiable", Reason: "probe helper missing"},
		},
	}}}
	beforeHB := time.Now()
	if err := stream.Send(hb); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	wantAcks := []struct {
		id       string
		accepted bool
	}{
		{"evt-exec-1", true},
		{"evt-rpath-1", true},
		{"evt-invalid", false},
	}
	for _, want := range wantAcks {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv ack for %s: %v", want.id, err)
		}
		ack := resp.GetAck()
		if ack == nil {
			t.Fatalf("expected ack for %s, got %T", want.id, resp.GetPayload())
		}
		if ack.GetEventId() != want.id || ack.GetAccepted() != want.accepted {
			t.Errorf("ack: got (%q, %v), want (%q, %v)",
				ack.GetEventId(), ack.GetAccepted(), want.id, want.accepted)
		}
	}

	// Half-close and drain: the server handler returns only after it has
	// processed every message, including the trailing heartbeat.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected io.EOF after close, got %v", err)
	}
	afterHB := time.Now()

	wantExec := &event.HookEvent{
		ID:          "evt-exec-1",
		Timestamp:   ts,
		HostID:      hostID,
		Hostname:    "web-enrolled",
		EventType:   event.EventExecInjection,
		Severity:    event.SeverityAlert,
		PID:         4242,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		Comm:        "target",
		Cmdline:     "/usr/bin/target --flag",
		ExePath:     "/usr/bin/target",
		ExeHash:     "sha256:exe",
		CgroupPath:  "/sys/fs/cgroup/user.slice",
		ContainerID: "ctr-abc",
		Namespace:   "prod",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			LibraryHash:  "sha256:lib",
			TargetBinary: "/usr/bin/target",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	wantRpath := &event.HookEvent{
		ID:        "evt-rpath-1",
		Timestamp: ts,
		HostID:    hostID,
		Hostname:  "web-enrolled",
		EventType: event.EventElfRpath,
		Severity:  event.SeverityCritical,
		PID:       4243,
		ExePath:   "/opt/app/bin/app",
		ElfRpathDetail: &event.ElfRpathDetail{
			HasRpath:   true,
			HasRunpath: true,
			RpathRaw:   "/tmp/evil:$ORIGIN/../lib",
			RunpathRaw: "/opt/app/lib",
			Entries: []event.RpathEntry{
				{Path: "/tmp/evil", Risk: event.RpathRiskCritical, Reason: "world-writable", Exists: true, IsRpath: true},
				{Path: "$ORIGIN/../lib", Risk: event.RpathRiskLow, Reason: "origin-relative", Exists: true, IsRpath: true},
				{Path: "/opt/app/lib", Risk: event.RpathRiskMedium, Reason: "non-standard", Exists: false, IsRpath: false},
			},
			HighestRisk:    event.RpathRiskCritical,
			UsesOrigin:     true,
			UsesDeprecated: true,
			IsSetuid:       true,
		},
	}

	store.mu.Lock()
	gotEvents := store.events
	gotHB, hbOK := store.heartbeats[hostID]
	_, spoofedHB := store.heartbeats["host-1"]
	store.mu.Unlock()

	if len(gotEvents) != 2 {
		t.Fatalf("stored events: got %d, want 2", len(gotEvents))
	}
	for i, want := range []*event.HookEvent{wantExec, wantRpath} {
		got := *gotEvents[i]
		if !got.Timestamp.Equal(want.Timestamp) {
			t.Errorf("%s timestamp: got %v, want %v", want.ID, got.Timestamp, want.Timestamp)
		}
		got.Timestamp = want.Timestamp
		if !reflect.DeepEqual(&got, want) {
			t.Errorf("%s converted event mismatch:\n got  %+v\n want %+v", want.ID, &got, want)
		}
	}

	if !hbOK {
		t.Fatal("heartbeat was not recorded under the certificate's host ID")
	}
	if spoofedHB {
		t.Error("heartbeat was recorded under the host ID in the message")
	}
	// The server records its own receive time, not the bus's timestamp.
	if gotHB.ReceivedAt.Before(beforeHB) || gotHB.ReceivedAt.After(afterHB) {
		t.Errorf("stored heartbeat time %v is not the receive time (between %v and %v)", gotHB.ReceivedAt, beforeHB, afterHB)
	}
	if gotHB.AgentVersion != "1.2.3" {
		t.Errorf("heartbeat agent version: got %q", gotHB.AgentVersion)
	}
	wantSensors := []event.SensorHealth{
		{Name: "bpf_syscall", Status: "alive"},
		{Name: "dlopen_monitor", Status: "unverifiable", Reason: "probe helper missing"},
	}
	if !reflect.DeepEqual(gotHB.Sensors, wantSensors) {
		t.Errorf("heartbeat sensors: got %+v, want %+v", gotHB.Sensors, wantSensors)
	}
	if last, ok := ing.GetHostLastHeartbeat(hostID); !ok || !last.Equal(gotHB.ReceivedAt) {
		t.Errorf("tracked heartbeat: got (%v, %v), want (%v, true)", last, ok, gotHB.ReceivedAt)
	}

	// Accepted events are also broadcast on the event channel.
	for _, wantID := range []string{"evt-exec-1", "evt-rpath-1"} {
		select {
		case evt := <-ing.GetEventChannel():
			if evt.ID != wantID {
				t.Errorf("broadcast event: got %q, want %q", evt.ID, wantID)
			}
		default:
			t.Fatalf("broadcast event %s missing", wantID)
		}
	}
}

// TestWire_HostCannotSendAsAnother has host A send an event and a heartbeat
// that name host B. Both must be recorded as host A's; host B's record must
// change only when B itself sends.
func TestWire_HostCannotSendAsAnother(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	w := enrServe(t, pki, NewIngestionServer(IngestionConfig{Store: store}), tls.RequireAndVerifyClientCert, false)
	hostA, hostB := uuid.New().String(), uuid.New().String()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	send := func(cert *tls.Certificate, eventID, claimedHost string) {
		t.Helper()
		stream, err := w.enrDial(t, cert, false).StreamEvents(ctx)
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		msgs := []*hookmonv1.AgentMessage{
			{Payload: &hookmonv1.AgentMessage_Event{Event: &hookmonv1.HookEvent{
				Id: eventID, Timestamp: timestamppb.Now(), HostId: claimedHost, Hostname: "x",
				EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD, Severity: hookmonv1.Severity_SEVERITY_WARN,
			}}},
			{Payload: &hookmonv1.AgentMessage_Heartbeat{Heartbeat: &hookmonv1.Heartbeat{
				HostId: claimedHost, AgentVersion: "from-" + eventID,
			}}},
		}
		for _, m := range msgs {
			if err := stream.Send(m); err != nil {
				t.Fatalf("send: %v", err)
			}
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("recv ack: %v", err)
		}
		if err := stream.CloseSend(); err != nil {
			t.Fatalf("close send: %v", err)
		}
		if _, err := stream.Recv(); err != io.EOF {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	}

	send(enrHostCert(t, pki, hostA), "spoof", hostB)

	store.mu.Lock()
	if len(store.events) != 1 {
		t.Fatalf("stored events: got %d, want 1", len(store.events))
	}
	if store.events[0].HostID != hostA {
		t.Errorf("event from A naming B: stored as %q, want host A %q", store.events[0].HostID, hostA)
	}
	if _, ok := store.heartbeats[hostB]; ok {
		t.Error("host A's heartbeat updated host B")
	}
	if hb := store.heartbeats[hostA]; hb == nil || hb.AgentVersion != "from-spoof" {
		t.Errorf("host A's heartbeat not recorded as A: %+v", hb)
	}
	store.mu.Unlock()

	send(enrHostCert(t, pki, hostB), "honest", hostB)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 2 {
		t.Fatalf("stored events: got %d, want 2", len(store.events))
	}
	if store.events[1].HostID != hostB {
		t.Errorf("event from B: stored as %q, want %q", store.events[1].HostID, hostB)
	}
	if hb := store.heartbeats[hostB]; hb == nil || hb.AgentVersion != "from-honest" {
		t.Errorf("host B's heartbeat: %+v", hb)
	}
}

// TestWire_StreamNeedsHostCert serves the stream on a listener that lets
// clients connect without a certificate, so the handler's own check is what
// refuses them. In production the listener also refuses them at the
// handshake (RequireAndVerifyClientCert).
func TestWire_StreamNeedsHostCert(t *testing.T) {
	store := newMemStore()
	pki := enrpki.New(t)
	w := enrServe(t, pki, NewIngestionServer(IngestionConfig{Store: store}), tls.VerifyClientCertIfGiven, false)

	notBus := pki.ClientCert(t, uuid.New().String(), "not-a-bus")
	for name, cert := range map[string]*tls.Certificate{
		"no certificate":          nil,
		"certificate not for bus": &notBus,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream, err := w.enrDial(t, cert, false).StreamEvents(ctx)
			if err == nil {
				_ = stream.Send(&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: &hookmonv1.HookEvent{
					Id: "e", Timestamp: timestamppb.Now(), HostId: uuid.New().String(),
					EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
				}}})
				_, err = stream.Recv()
			}
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("got %v, want Unauthenticated", err)
			}
		})
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 0 {
		t.Errorf("stored %d events from unauthenticated streams", len(store.events))
	}
}

// TestWire_InsecureUsesMessageHostID covers the development mode: a server
// running without TLS has no certificate to go on and records the host ID
// each message names.
func TestWire_InsecureUsesMessageHostID(t *testing.T) {
	store := newMemStore()
	w := enrServe(t, nil, NewIngestionServer(IngestionConfig{Store: store, Insecure: true}), tls.NoClientCert, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := w.enrDial(t, nil, true).StreamEvents(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&hookmonv1.AgentMessage{Payload: &hookmonv1.AgentMessage_Event{Event: &hookmonv1.HookEvent{
		Id: "e1", Timestamp: timestamppb.Now(), HostId: "dev-host", EventType: hookmonv1.EventType_EVENT_TYPE_BPF_LOAD,
	}}}); err != nil {
		t.Fatal(err)
	}
	if resp, err := stream.Recv(); err != nil || !resp.GetAck().GetAccepted() {
		t.Fatalf("ack: %v %v", resp, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 1 {
		t.Fatalf("stored events: got %d, want 1", len(store.events))
	}
	if store.events[0].HostID != "dev-host" {
		t.Errorf("insecure mode host ID: got %q, want dev-host", store.events[0].HostID)
	}
}

// enrEnrollServer serves an Enroller on a server-auth-only TLS listener, as
// the enrollment port does, with three tokens: reusable, single-use and
// expired.
func enrEnrollServer(t *testing.T, store EnrollStore) (*enrWire, map[string]string) {
	t.Helper()
	pki := enrpki.New(t)
	ca, err := hcrypto.ParseCA(pki.CACertPEM, pki.CAKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{
		"reusable":   "reusable-0123456789abcdef0123456789abcdef",
		"single-use": "singleuse-0123456789abcdef0123456789abcdef",
		"expired":    "expired-0123456789abcdef0123456789abcdef",
	}
	now := time.Now()
	tokens, err := hcrypto.NewTokenSet([]hcrypto.EnrollmentToken{
		{Name: "reusable", Secret: secrets["reusable"], Expires: now.Add(time.Hour)},
		{Name: "single-use", Secret: secrets["single-use"], Expires: now.Add(time.Hour), SingleUse: true},
		{Name: "expired", Secret: secrets["expired"], Expires: now.Add(-time.Minute)},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnroller(EnrollerConfig{Store: store, Tokens: tokens, CA: ca})
	return enrServe(t, pki, e, tls.NoClientCert, false), secrets
}

func TestWire_Enroll(t *testing.T) {
	store := newMemStore()
	w, secrets := enrEnrollServer(t, store)
	client := w.enrDial(t, nil, false) // a bus enrolling has no certificate

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, csrPEM, err := hcrypto.GenerateAgentKeypair("web-02")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Enroll(ctx, &hookmonv1.EnrollRequest{
		EnrollmentToken: secrets["reusable"],
		Hostname:        "web-02",
		Csr:             csrPEM,
		OsInfo:          "Ubuntu 24.04",
		AgentVersion:    "1.2.3",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := uuid.Parse(resp.GetHostId()); err != nil {
		t.Errorf("host ID %q is not a UUID", resp.GetHostId())
	}

	// The signed certificate is a real client certificate for the assigned
	// host ID, issued by the CA in the response.
	block, _ := pem.Decode(resp.GetSignedCert())
	if block == nil {
		t.Fatalf("signed cert is not PEM: %q", resp.GetSignedCert())
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	if cert.IsCA {
		t.Error("Enroll returned a CA certificate as the signed certificate")
	}
	if id, err := hcrypto.HostIDFromCert(cert); err != nil || id != resp.GetHostId() {
		t.Errorf("certificate host ID: got (%q, %v), want %q", id, err, resp.GetHostId())
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(resp.GetCaCert()) {
		t.Fatal("CA cert in response does not parse")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("signed cert does not verify against the returned CA: %v", err)
	}

	store.mu.Lock()
	hosts := append([]*event.Host(nil), store.hosts...)
	store.mu.Unlock()
	if len(hosts) != 1 {
		t.Fatalf("registered hosts: got %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.ID != resp.GetHostId() || h.Hostname != "web-02" || h.OSInfo != "Ubuntu 24.04" ||
		h.AgentVersion != "1.2.3" || h.Status != event.HostOnline {
		t.Errorf("registered host mismatch: %+v", h)
	}

	// A reusable token enrolls again, as a new host.
	resp2, err := client.Enroll(ctx, &hookmonv1.EnrollRequest{EnrollmentToken: secrets["reusable"], Hostname: "web-03", Csr: csrPEM})
	if err != nil || resp2.GetHostId() == resp.GetHostId() {
		t.Errorf("second enrollment with a reusable token: got (%v, %v)", resp2.GetHostId(), err)
	}
}

func TestWire_EnrollRejects(t *testing.T) {
	store := newMemStore()
	w, secrets := enrEnrollServer(t, store)
	client := w.enrDial(t, nil, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, csrPEM, err := hcrypto.GenerateAgentKeypair("web")
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(token string, csr []byte) error {
		_, err := client.Enroll(ctx, &hookmonv1.EnrollRequest{EnrollmentToken: token, Hostname: "web", Csr: csr})
		return err
	}

	// Single-use: the first enrollment works, the second is refused.
	if err := enroll(secrets["single-use"], csrPEM); err != nil {
		t.Fatalf("first use of single-use token: %v", err)
	}
	if err := enroll(secrets["single-use"], csrPEM); status.Code(err) != codes.PermissionDenied {
		t.Errorf("reused single-use token: got %v, want PermissionDenied", err)
	}

	for name, tc := range map[string]struct {
		token string
		csr   []byte
		want  codes.Code
	}{
		"invalid token": {"0123456789abcdef0123456789abcdef-wrong", csrPEM, codes.PermissionDenied},
		"expired token": {secrets["expired"], csrPEM, codes.PermissionDenied},
		"no token":      {"", csrPEM, codes.InvalidArgument},
		"no CSR":        {secrets["reusable"], nil, codes.InvalidArgument},
		"garbage CSR":   {secrets["reusable"], []byte("not a csr"), codes.InvalidArgument},
	} {
		if err := enroll(tc.token, tc.csr); status.Code(err) != tc.want {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.hosts) != 1 {
		t.Errorf("registered hosts: got %d, want 1 (only the first single-use enrollment)", len(store.hosts))
	}
}

// TestWire_EnrollAndStreamAreSeparate checks each listener serves only its
// own RPC: no event stream on the enrollment listener, which accepts
// clients without certificates, and no enrollment on the stream listener.
func TestWire_EnrollAndStreamAreSeparate(t *testing.T) {
	w, _ := enrEnrollServer(t, newMemStore())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := w.enrDial(t, nil, false).StreamEvents(ctx)
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("StreamEvents on the enrollment listener: got %v, want Unimplemented", err)
	}

	pki := enrpki.New(t)
	ing := enrServe(t, pki, NewIngestionServer(IngestionConfig{Store: newMemStore()}), tls.RequireAndVerifyClientCert, false)
	_, err = ing.enrDial(t, enrHostCert(t, pki, uuid.New().String()), false).Enroll(ctx, &hookmonv1.EnrollRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("Enroll on the stream listener: got %v, want Unimplemented", err)
	}
}
