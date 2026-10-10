package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/test/enrpki"
)

func TestCheckTLS(t *testing.T) {
	cases := []struct {
		name string
		tls  TLSConfig
		ok   bool
	}{
		{"no certificate", TLSConfig{}, false},
		{"key and CA but no certificate", TLSConfig{KeyFile: "s.key", CAFile: "ca.crt"}, false},
		{"certificate", TLSConfig{CertFile: "s.crt", KeyFile: "s.key", CAFile: "ca.crt"}, true},
		{"insecure", TLSConfig{Insecure: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TLS = c.tls
			err := cfg.CheckTLS()
			if c.ok && err != nil {
				t.Errorf("CheckTLS: %v", err)
			}
			if !c.ok && !errors.Is(err, ErrNoTLS) {
				t.Errorf("CheckTLS: got %v, want ErrNoTLS", err)
			}
		})
	}
	if !strings.Contains(ErrNoTLS.Error(), "--insecure") || !strings.Contains(ErrNoTLS.Error(), "tls.cert_file") {
		t.Errorf("ErrNoTLS does not say how to fix it: %q", ErrNoTLS)
	}
}

// TestRun_RefusesWithoutTLS starts a server with the default config: no
// certificate and no --insecure. Run must fail with ErrNoTLS before it
// connects to the database or binds a listener. The same config with
// Insecure gets past that check and fails on the (unreachable) database
// instead, so the TLS check is what stopped the first run.
func TestRun_RefusesWithoutTLS(t *testing.T) {
	secRun := func(cfg Config) (ready bool, err error) {
		cfg.Database.URL = "postgres://hookmon@127.0.0.1:1/hookmon?sslmode=disable&connect_timeout=2"
		cfg.GRPCAddr, cfg.EnrollAddr, cfg.HTTPAddr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
		srv := New(cfg, zap.NewNop())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err = srv.Run(ctx)
		select {
		case <-srv.Ready():
			return true, err
		default:
			return false, err
		}
	}

	ready, err := secRun(DefaultConfig())
	if !errors.Is(err, ErrNoTLS) {
		t.Fatalf("Run without TLS: got %v, want ErrNoTLS", err)
	}
	if ready {
		t.Error("listeners were bound before the TLS check")
	}

	insecure := DefaultConfig()
	insecure.TLS.Insecure = true
	_, err = secRun(insecure)
	if err == nil || errors.Is(err, ErrNoTLS) || !strings.Contains(err.Error(), "connect to database") {
		t.Errorf("Run with Insecure: got %v, want a database connection error", err)
	}
}

// TestServeHTTP_TLS serves a handler the way Run serves the REST API: a
// client that trusts the CA gets the response over TLS, a plain HTTP
// request to the same port is refused, and a client that does not trust
// the CA fails the handshake.
func TestServeHTTP_TLS(t *testing.T) {
	pki := enrpki.New(t)
	tlsCfg, err := hcrypto.LoadHTTPServerTLS(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHTTP(ctx, srv, lis, tlsCfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serveHTTP: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serveHTTP did not return after cancel")
		}
	})
	addr := lis.Addr().String()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CACertPEM)
	trusted := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := trusted.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" || resp.TLS == nil {
		t.Errorf("HTTPS GET: status %d, body %q, TLS %v", resp.StatusCode, body, resp.TLS != nil)
	}

	plain := &http.Client{Timeout: 10 * time.Second}
	resp, err = plain.Get("http://" + addr + "/")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || string(body) == "ok" {
			t.Errorf("plain HTTP GET to the TLS port: status %d, body %q", resp.StatusCode, body)
		}
	}

	untrusted := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
	if _, err := untrusted.Get("https://" + addr + "/"); err == nil {
		t.Error("a client without the CA accepted the server certificate")
	}
}
