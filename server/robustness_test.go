package server

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/ingestion"
)

// TestNewHTTPServer_Timeouts: the REST server bounds slow clients. Before
// step 7f it had no timeouts at all, so a client that sent its headers one
// byte at a time held a connection and a goroutine for ever.
func TestNewHTTPServer_Timeouts(t *testing.T) {
	srv := newHTTPServer(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadHeaderTimeout > 30*time.Second {
		t.Errorf("ReadHeaderTimeout %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Errorf("ReadTimeout %v, IdleTimeout %v, MaxHeaderBytes %d", srv.ReadTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout %v would cut off the WebSocket feed", srv.WriteTimeout)
	}

	// The header timeout is enforced: a client that never finishes its
	// headers is disconnected. (Shortened here so the test is quick.)
	srv.ReadHeaderTimeout = 200 * time.Millisecond
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveHTTP(ctx, srv, lis, nil)
	conn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = bufio.NewReader(conn).ReadString('\n')
	if err == nil {
		// A 408 or 400 line is also a disconnect; read on to EOF.
		_, err = bufio.NewReader(conn).ReadString(0)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection still open after %v with headers unfinished", time.Since(start))
	}
}

// TestWatchdog_OfflineReachesFeed: the watchdog's AGENT_OFFLINE goes to the
// connectors and to the WebSocket feed. Before step 7f it reached only the
// connectors.
func TestWatchdog_OfflineReachesFeed(t *testing.T) {
	store := &enrWatchdogStore{hosts: map[string]*event.Host{
		"stale": {ID: "stale", Hostname: "web-stale", Status: event.HostOnline, LastHeartbeat: time.Now().Add(-time.Minute)},
	}}
	conns := &enrSink{}
	feed := ingestion.NewIngestionServer(ingestion.IngestionConfig{})
	w := NewWatchdog(WatchdogConfig{CheckInterval: time.Second, HeartbeatTimeout: 10 * time.Second},
		store, statusFanout{conns, feed}, zap.NewNop())
	w.check(context.Background())

	if len(conns.evts) != 1 || conns.evts[0].EventType != event.EventAgentOffline {
		t.Fatalf("connectors got %+v", conns.evts)
	}
	select {
	case got := <-feed.GetEventChannel():
		if got != conns.evts[0] {
			t.Errorf("feed got %+v, want the AGENT_OFFLINE", got)
		}
	default:
		t.Fatal("AGENT_OFFLINE did not reach the WebSocket feed")
	}
}
