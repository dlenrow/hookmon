package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	// WSProtocol is the WebSocket subprotocol of the live event feed. A
	// browser client offers it with its token (WSTokenProtocolPrefix), and
	// the server selects it, so the token is never echoed back.
	WSProtocol = "hookmon.v1"

	// WSTokenProtocolPrefix carries the API token in the handshake. The
	// browser WebSocket API cannot set an Authorization header, and a token
	// in the URL is written to access and proxy logs, so a browser offers
	// "hookmon.bearer.<token as unpadded base64url>" in
	// Sec-WebSocket-Protocol, next to WSProtocol. Base64url keeps any token
	// within the characters a subprotocol may hold. Clients that can set
	// headers send "Authorization: Bearer <token>" instead.
	WSTokenProtocolPrefix = "hookmon.bearer."

	wsWriteWait  = 10 * time.Second
	wsPongWait   = 60 * time.Second
	wsPingPeriod = 30 * time.Second
	// wsReadLimit bounds a client message; the feed reads them only to see
	// the connection close.
	wsReadLimit = 4096
)

// ParseOrigins checks configured WebSocket origins ("https://host[:port]")
// and returns them in the canonical form the Origin check compares.
func ParseOrigins(origins []string) ([]string, error) {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("allowed origin %q: want scheme://host[:port], such as https://hookmon.example.com", o)
		}
		out = append(out, canonOrigin(u))
	}
	return out, nil
}

func canonOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// SetAllowedOrigins sets the origins, besides the server's own, whose pages
// may open the WebSocket feed. Each is "scheme://host[:port]".
func (s *Server) SetAllowedOrigins(origins []string) error {
	canon, err := ParseOrigins(origins)
	if err != nil {
		return err
	}
	s.allowedOrigins = make(map[string]bool, len(canon))
	for _, o := range canon {
		s.allowedOrigins[o] = true
	}
	return nil
}

// originAllowed reports whether a WebSocket handshake may proceed given its
// Origin header. A browser always sends Origin, so a page on another site
// cannot open the feed with a token it obtained some other way. The
// server's own origin is allowed: the Origin's host equals the Host the
// request was sent to, as for gorilla/websocket's default check. So is
// every configured origin. A handshake with no Origin is not from a
// browser and is allowed; it still needs a valid token. "null" and
// malformed origins are refused.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return s.allowedOrigins[canonOrigin(u)]
}

// wsToken returns the API token a handshake presents: from the
// Authorization header, read as REST reads it, or from a
// WSTokenProtocolPrefix subprotocol. It returns an error, for the client,
// when there is none or it cannot be decoded. A token in the URL is
// refused, so it never reaches a log.
func wsToken(r *http.Request) (string, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		return bearerToken(h), nil
	}
	for _, p := range websocket.Subprotocols(r) {
		enc, ok := strings.CutPrefix(p, WSTokenProtocolPrefix)
		if !ok {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			return "", errors.New("token subprotocol is not unpadded base64url")
		}
		return string(raw), nil
	}
	if r.URL.Query().Has("token") {
		return "", errors.New("a token in the URL is not accepted: offer it as the " + WSTokenProtocolPrefix + "<base64url> subprotocol, or send an Authorization header")
	}
	return "", errors.New("missing token: offer the " + WSTokenProtocolPrefix + "<base64url> subprotocol, or send an Authorization header")
}

// handleWebSocket streams every event the server processes, as JSON text
// messages, from the moment the handshake completes. Each client has its
// own subscription to the hub. A client that falls more than the hub's
// buffer behind is closed with 1013 (try again later); it should
// reconnect and reload recent events over REST.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		s.logger.Warn("websocket refused: origin not allowed",
			zap.String("origin", r.Header.Get("Origin")), zap.String("host", r.Host), zap.String("remote", r.RemoteAddr))
		writeError(w, http.StatusForbidden, "origin not allowed")
		return
	}
	token, err := wsToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if token == "" || s.auth == nil || !s.auth.validateToken(token) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "live event feed is not available")
		return
	}
	// Subscribe before the upgrade, so the client gets every event from the
	// moment it is connected.
	sub := s.hub.Subscribe()
	if sub == nil {
		writeError(w, http.StatusServiceUnavailable, "server is shutting down")
		return
	}
	defer s.hub.Unsubscribe(sub)

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		Subprotocols:    []string{WSProtocol},
		CheckOrigin:     s.originAllowed,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has answered the request.
		s.logger.Debug("websocket upgrade failed", zap.Error(err))
		return
	}
	defer conn.Close()

	s.logger.Info("websocket client connected", zap.String("remote", r.RemoteAddr))

	conn.SetReadLimit(wsReadLimit)
	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})

	// Read (and discard) client messages, to process pongs and see the
	// client close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(wsPingPeriod)
	defer ping.Stop()

	for {
		select {
		case <-done:
			return
		case evt, ok := <-sub.Events():
			if !ok {
				code, text := websocket.CloseGoingAway, "server shutting down"
				if sub.Lagged() {
					code, text = websocket.CloseTryAgainLater, "fell behind the event feed; reconnect"
					s.logger.Warn("websocket client dropped: fell behind the event feed", zap.String("remote", r.RemoteAddr))
				}
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(time.Second))
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				s.logger.Debug("websocket write failed", zap.Error(err))
				return
			}
		case <-ping.C:
			conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
