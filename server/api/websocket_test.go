package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

const dashToken = "tok/with+chars=" // not valid in a subprotocol as is

// dashWSServer runs the API with a hub over plain HTTP.
func dashWSServer(t *testing.T, hub *Hub, origins ...string) *httptest.Server {
	t.Helper()
	s := NewServer(newPolStore(), zap.NewNop(), hub)
	if err := s.SetAllowedOrigins(origins); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Router([]string{dashToken}, nil))
	t.Cleanup(srv.Close)
	return srv
}

func dashWSURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/ws/events"
}

func dashTokenProto(tok string) string {
	return WSTokenProtocolPrefix + base64.RawURLEncoding.EncodeToString([]byte(tok))
}

func dashDial(url string, h http.Header, protocols ...string) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{Subprotocols: protocols, HandshakeTimeout: 5 * time.Second}
	return d.Dial(url, h)
}

func dashBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestWebSocket_TokenAndOrigin(t *testing.T) {
	srv := dashWSServer(t, NewHub(8), "https://dash.example.com:5173")
	url := dashWSURL(srv)
	self := "http://" + srv.Listener.Addr().String()
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	good := []string{WSProtocol, dashTokenProto(dashToken)}

	cases := []struct {
		name      string
		url       string
		header    http.Header
		protocols []string
		code      int
		body      string
	}{
		{"no token", url, hdr("Origin", self), []string{WSProtocol}, http.StatusUnauthorized, "missing token"},
		{"wrong token", url, hdr("Origin", self), []string{WSProtocol, dashTokenProto("nope")}, http.StatusUnauthorized, "invalid token"},
		{"token not base64url", url, hdr("Origin", self), []string{WSProtocol, WSTokenProtocolPrefix + "a.b"}, http.StatusUnauthorized, "base64url"},
		{"token in the URL", url + "?token=" + dashToken, hdr("Origin", self), []string{WSProtocol}, http.StatusUnauthorized, "URL is not accepted"},
		{"wrong bearer header", url, hdr("Authorization", "Bearer nope"), nil, http.StatusUnauthorized, "invalid token"},
		{"another site", url, hdr("Origin", "https://evil.example"), good, http.StatusForbidden, "origin not allowed"},
		{"null origin", url, hdr("Origin", "null"), good, http.StatusForbidden, "origin not allowed"},
		{"configured origin, other port", url, hdr("Origin", "https://dash.example.com"), good, http.StatusForbidden, "origin not allowed"},
		{"another site, no token", url, hdr("Origin", "https://evil.example"), nil, http.StatusForbidden, "origin not allowed"},

		{"own origin, subprotocol token", url, hdr("Origin", self), good, http.StatusSwitchingProtocols, ""},
		{"configured origin", url, hdr("Origin", "https://DASH.example.com:5173"), good, http.StatusSwitchingProtocols, ""},
		{"no Origin (not a browser), bearer header", url, hdr("Authorization", "Bearer "+dashToken), nil, http.StatusSwitchingProtocols, ""},
	}
	for _, c := range cases {
		conn, resp, err := dashDial(c.url, c.header, c.protocols...)
		if resp == nil {
			t.Errorf("%s: no response: %v", c.name, err)
			continue
		}
		if resp.StatusCode != c.code {
			t.Errorf("%s: status %d, want %d (%v %s)", c.name, resp.StatusCode, c.code, err, dashBody(resp))
		}
		if c.code != http.StatusSwitchingProtocols {
			if conn != nil {
				conn.Close()
			}
			if b := dashBody(resp); !strings.Contains(b, c.body) {
				t.Errorf("%s: body %q, want it to contain %q", c.name, b, c.body)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		// The server selects hookmon.v1 and never echoes the token.
		if c.protocols != nil && conn.Subprotocol() != WSProtocol {
			t.Errorf("%s: subprotocol %q, want %q", c.name, conn.Subprotocol(), WSProtocol)
		}
		if p := resp.Header.Get("Sec-WebSocket-Protocol"); strings.Contains(p, "bearer") {
			t.Errorf("%s: response echoes the token protocol: %q", c.name, p)
		}
		conn.Close()
	}
}

func TestParseOrigins(t *testing.T) {
	got, err := ParseOrigins([]string{"https://Hookmon.Example.com", "http://localhost:5173/"})
	if err != nil || strings.Join(got, " ") != "https://hookmon.example.com http://localhost:5173" {
		t.Errorf("got %v %v", got, err)
	}
	for _, bad := range []string{"hookmon.example.com", "ftp://x", "https://", "https://x/path", "https://x?q=1", "https://u@x", "*"} {
		if _, err := ParseOrigins([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// dashRead reads n events from conn.
func dashRead(t *testing.T, conn *websocket.Conn, n int) []string {
	t.Helper()
	var ids []string
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(ids) < n {
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("after %d events: %v", len(ids), err)
		}
		var e event.HookEvent
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	return ids
}

// Two clients (two dashboard tabs) each get every event, in order.
func TestWebSocket_TwoClientsGetEveryEvent(t *testing.T) {
	hub := NewHub(256)
	srv := dashWSServer(t, hub)
	h := http.Header{"Origin": {"http://" + srv.Listener.Addr().String()}}
	var conns []*websocket.Conn
	for i := 0; i < 2; i++ {
		c, resp, err := dashDial(dashWSURL(srv), h, WSProtocol, dashTokenProto(dashToken))
		if err != nil {
			t.Fatalf("dial %d: %v %s", i, err, dashBody(resp))
		}
		defer c.Close()
		conns = append(conns, c)
	}
	// Each handshake subscribes before it completes.
	if n := hub.Stats().Subscribers; n != 2 {
		t.Fatalf("subscribers: %d, want 2", n)
	}
	const n = 100
	for i := 0; i < n; i++ {
		hub.Publish(dashEvt(i))
	}
	for k, c := range conns {
		ids := dashRead(t, c, n)
		for i, id := range ids {
			if id != dashEvt(i).ID {
				t.Fatalf("client %d: event %d is %s, want %s", k, i, id, dashEvt(i).ID)
			}
		}
	}

	// A client that leaves is unsubscribed; the other keeps receiving.
	conns[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for hub.Stats().Subscribers != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("subscribers after a close: %d, want 1", hub.Stats().Subscribers)
		}
		time.Sleep(10 * time.Millisecond)
	}
	hub.Publish(dashEvt(n))
	if ids := dashRead(t, conns[1], 1); ids[0] != dashEvt(n).ID {
		t.Errorf("after the other left: %v", ids)
	}
}

// A client that does not keep up is closed with 1013 (try again later)
// once it falls a buffer behind. Publishing never waits for it.
func TestWebSocket_SlowClientClosedWith1013(t *testing.T) {
	hub := NewHub(2)
	srv := dashWSServer(t, hub)
	c, resp, err := dashDial(dashWSURL(srv), http.Header{"Authorization": {"Bearer " + dashToken}})
	if err != nil {
		t.Fatalf("dial: %v %s", err, dashBody(resp))
	}
	defer c.Close()

	// Large events, published while the client reads nothing, overrun the
	// socket buffers and the subscriber's buffer of 2.
	big := strings.Repeat("x", 512<<10)
	const n = 128
	start := time.Now()
	for i := 0; i < n; i++ {
		e := dashEvt(i)
		e.Cmdline = big
		hub.Publish(e)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("publishing %d events took %v with a stalled client", n, d)
	}

	got := 0
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		_, _, err := c.ReadMessage()
		if err == nil {
			got++
			continue
		}
		var ce *websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != websocket.CloseTryAgainLater {
			t.Fatalf("after %d events: %v, want close 1013", got, err)
		}
		break
	}
	if got >= n {
		t.Errorf("slow client got all %d events; it should have been dropped", got)
	}
	t.Logf("slow client got %d of %d events, then close 1013", got, n)
	if st := hub.Stats(); st.Lagged != 1 || st.Subscribers != 0 {
		t.Errorf("hub stats: %+v", st)
	}
}

func TestWebSocket_NoHubIs503(t *testing.T) {
	srv := dashWSServer(t, nil)
	_, resp, _ := dashDial(dashWSURL(srv), http.Header{"Authorization": {"Bearer " + dashToken}})
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no hub: %v", resp)
	}
}
