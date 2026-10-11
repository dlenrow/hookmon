package crypto_test

// The TLS credential loaders in mtls.go, through real handshakes on
// loopback: the mutual-TLS listener needs a client certificate from the CA
// and TLS 1.3, the enrollment listener needs none, and the REST listener
// accepts TLS 1.2 for browsers. Fix plan step 7h.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// t7hHandshake runs a server and a client handshake against each other over
// a loopback TCP connection and returns each side's result. authority is
// what a gRPC client dials ("localhost:<port>" style); the port is filled in.
func t7hHandshake(t *testing.T, server, client credentials.TransportCredentials, authorityHost string) (srvInfo, cliInfo credentials.AuthInfo, srvErr, cliErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		info credentials.AuthInfo
		err  error
	}
	srvDone := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- result{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		// Under TLS 1.3 the client can finish before the server has
		// checked the client certificate, so a refusal shows up here.
		_, info, err := server.ServerHandshake(conn)
		srvDone <- result{info: info, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	tconn, info, err := client.ClientHandshake(ctx, net.JoinHostPort(authorityHost, port), conn)
	cliInfo, cliErr = info, err
	if err == nil {
		defer tconn.Close()
	}
	r := <-srvDone
	return r.info, cliInfo, r.err, cliErr
}

// t7hTLSState returns the connection state in a TLS AuthInfo.
func t7hTLSState(t *testing.T, info credentials.AuthInfo) tls.ConnectionState {
	t.Helper()
	ti, ok := info.(credentials.TLSInfo)
	if !ok {
		t.Fatalf("AuthInfo is %T, want credentials.TLSInfo", info)
	}
	return ti.State
}

// t7hWritePair writes a tls.Certificate's leaf and key as PEM files.
func t7hWritePair(t *testing.T, dir, name string, c tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func t7hServerCreds(t *testing.T, p *enrpki.PKI) credentials.TransportCredentials {
	t.Helper()
	c, err := hcrypto.LoadServerTLS(p.ServerCertFile, p.ServerKeyFile, p.CACertFile)
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	return c
}

func t7hClientCreds(t *testing.T, p *enrpki.PKI, caFile, cn string) credentials.TransportCredentials {
	t.Helper()
	certFile, keyFile := t7hWritePair(t, t.TempDir(), "bus", p.ClientCert(t, cn, hcrypto.HostCertOrganization))
	c, err := hcrypto.LoadClientTLS(certFile, keyFile, caFile, "localhost")
	if err != nil {
		t.Fatalf("LoadClientTLS: %v", err)
	}
	return c
}

// TestLoadServerTLS_MutualTLS: the gRPC listener accepts a bus certificate
// from its CA over TLS 1.3, and each side sees the other's certificate.
func TestLoadServerTLS_MutualTLS(t *testing.T) {
	p := enrpki.New(t)
	hostID := uuid.NewString()
	srv, cli, srvErr, cliErr := t7hHandshake(t, t7hServerCreds(t, p), t7hClientCreds(t, p, p.CACertFile, hostID), "localhost")
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake: server %v, client %v", srvErr, cliErr)
	}
	ss := t7hTLSState(t, srv)
	if ss.Version != tls.VersionTLS13 {
		t.Errorf("TLS version %x, want 1.3", ss.Version)
	}
	if len(ss.PeerCertificates) == 0 || ss.PeerCertificates[0].Subject.CommonName != hostID {
		t.Fatalf("server sees peer certificates %v, want CN %s", ss.PeerCertificates, hostID)
	}
	if len(ss.VerifiedChains) == 0 {
		t.Error("server did not verify the client chain")
	}
	if id, err := hcrypto.HostIDFromCert(ss.PeerCertificates[0]); err != nil || id != hostID {
		t.Errorf("HostIDFromCert = %q, %v", id, err)
	}
	cs := t7hTLSState(t, cli)
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != "hookmon-server" {
		t.Errorf("client sees %v, want the server certificate", cs.PeerCertificates)
	}
}

// TestLoadServerTLS_RefusesClients: no client certificate, a certificate
// from another CA, and TLS 1.2 are all refused by the server.
func TestLoadServerTLS_RefusesClients(t *testing.T) {
	p := enrpki.New(t)
	other := enrpki.New(t)

	noCert, err := hcrypto.EnrollClientTLS(p.CACertPEM, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	// A client that trusts p's CA but presents a certificate from other.
	foreignFile, foreignKey := t7hWritePair(t, t.TempDir(), "foreign", other.ClientCert(t, "host-b", hcrypto.HostCertOrganization))
	foreign, err := hcrypto.LoadClientTLS(foreignFile, foreignKey, p.CACertFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	// TLS 1.2 with a good certificate.
	good := p.ClientCert(t, "host-c", hcrypto.HostCertOrganization)
	tls12 := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{good},
		RootCAs:      p.CAPool(),
		ServerName:   "localhost",
		MaxVersion:   tls.VersionTLS12,
	})

	for name, client := range map[string]credentials.TransportCredentials{
		"no client certificate":       noCert,
		"certificate from another CA": foreign,
		"TLS 1.2":                     tls12,
	} {
		t.Run(name, func(t *testing.T) {
			srv, _, srvErr, _ := t7hHandshake(t, t7hServerCreds(t, p), client, "localhost")
			if srvErr == nil {
				t.Fatalf("server accepted the client: %+v", t7hTLSState(t, srv).PeerCertificates)
			}
			t.Logf("server refused: %v", srvErr)
		})
	}
}

// TestLoadClientTLS_VerifiesServer: a bus refuses a server whose
// certificate is not from its CA, or not for the name it expects.
func TestLoadClientTLS_VerifiesServer(t *testing.T) {
	p := enrpki.New(t)
	other := enrpki.New(t)

	// The bus trusts other's CA only.
	_, _, _, cliErr := t7hHandshake(t, t7hServerCreds(t, p), t7hClientCreds(t, p, other.CACertFile, "host-a"), "localhost")
	if cliErr == nil {
		t.Error("client accepted a server certificate from an untrusted CA")
	}

	// The right CA, the wrong name.
	certFile, keyFile := t7hWritePair(t, t.TempDir(), "bus", p.ClientCert(t, "host-a", hcrypto.HostCertOrganization))
	wrongName, err := hcrypto.LoadClientTLS(certFile, keyFile, p.CACertFile, "not-the-server.example")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, cliErr = t7hHandshake(t, t7hServerCreds(t, p), wrongName, "localhost")
	if cliErr == nil || !strings.Contains(cliErr.Error(), "not-the-server.example") {
		t.Errorf("client with the wrong server name: %v, want a name mismatch", cliErr)
	}
}

// TestLoadEnrollServerTLS: the enrollment listener authenticates itself
// and asks for no client certificate; an enrolling bus verifies it.
func TestLoadEnrollServerTLS(t *testing.T) {
	p := enrpki.New(t)
	other := enrpki.New(t)
	srvCreds, err := hcrypto.LoadEnrollServerTLS(p.ServerCertFile, p.ServerKeyFile)
	if err != nil {
		t.Fatalf("LoadEnrollServerTLS: %v", err)
	}

	// No server name: the host in the dial address (an IP SAN here).
	enroll, err := hcrypto.EnrollClientTLS(p.CACertPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	srv, cli, srvErr, cliErr := t7hHandshake(t, srvCreds, enroll, "127.0.0.1")
	if srvErr != nil || cliErr != nil {
		t.Fatalf("enroll handshake: server %v, client %v", srvErr, cliErr)
	}
	if ss := t7hTLSState(t, srv); len(ss.PeerCertificates) != 0 || ss.Version != tls.VersionTLS13 {
		t.Errorf("enroll server: %d peer certificates, version %x; want none, TLS 1.3", len(ss.PeerCertificates), ss.Version)
	}
	if cs := t7hTLSState(t, cli); len(cs.VerifiedChains) == 0 {
		t.Error("enrolling client did not verify the server")
	}

	// A bus given another CA refuses the server.
	wrongCA, err := hcrypto.EnrollClientTLS(other.CACertPEM, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, cliErr := t7hHandshake(t, srvCreds, wrongCA, "localhost"); cliErr == nil {
		t.Error("enrolling client accepted a server from an untrusted CA")
	}

	// LoadInsecureClientTLS verifies nothing: it connects to any server.
	// That is why the bus uses it only with --insecure.
	if _, _, srvErr, cliErr := t7hHandshake(t, srvCreds, hcrypto.LoadInsecureClientTLS(), "localhost"); srvErr != nil || cliErr != nil {
		t.Errorf("insecure client: server %v, client %v", srvErr, cliErr)
	}
}

// TestLoadHTTPServerTLS: the REST listener serves the server certificate,
// asks for no client certificate, and accepts TLS 1.2 (browsers) but not
// 1.1.
func TestLoadHTTPServerTLS(t *testing.T) {
	p := enrpki.New(t)
	cfg, err := hcrypto.LoadHTTPServerTLS(p.ServerCertFile, p.ServerKeyFile)
	if err != nil {
		t.Fatalf("LoadHTTPServerTLS: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert || cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 {
		t.Errorf("config: client auth %v, min version %x, %d certificates", cfg.ClientAuth, cfg.MinVersion, len(cfg.Certificates))
	}
	for _, c := range []struct {
		max uint16
		ok  bool
	}{{tls.VersionTLS13, true}, {tls.VersionTLS12, true}, {tls.VersionTLS11, false}} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		errc := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			errc <- tls.Server(conn, cfg).Handshake()
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		cliErr := tls.Client(conn, &tls.Config{RootCAs: p.CAPool(), ServerName: "localhost", MinVersion: tls.VersionTLS10, MaxVersion: c.max}).Handshake()
		srvErr := <-errc
		conn.Close()
		ln.Close()
		if ok := cliErr == nil && srvErr == nil; ok != c.ok {
			t.Errorf("client max TLS %x: client %v, server %v; want ok=%v", c.max, cliErr, srvErr, c.ok)
		}
	}
}

// TestTLSLoaders_BadFiles: every loader returns an error, not a panic or
// half-built credentials, for missing or malformed files.
func TestTLSLoaders_BadFiles(t *testing.T) {
	p := enrpki.New(t)
	other := enrpki.New(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	busCert, busKey := t7hWritePair(t, dir, "bus", p.ClientCert(t, "host-a"))

	cases := map[string]func() error{
		"server: missing cert": func() error { _, err := hcrypto.LoadServerTLS(missing, p.ServerKeyFile, p.CACertFile); return err },
		"server: key of other": func() error {
			_, err := hcrypto.LoadServerTLS(p.ServerCertFile, other.ServerKeyFile, p.CACertFile)
			return err
		},
		"server: missing CA":       func() error { _, err := hcrypto.LoadServerTLS(p.ServerCertFile, p.ServerKeyFile, missing); return err },
		"server: CA not PEM":       func() error { _, err := hcrypto.LoadServerTLS(p.ServerCertFile, p.ServerKeyFile, notPEM); return err },
		"enroll server: no key":    func() error { _, err := hcrypto.LoadEnrollServerTLS(p.ServerCertFile, missing); return err },
		"http server: no cert":     func() error { _, err := hcrypto.LoadHTTPServerTLS(missing, p.ServerKeyFile); return err },
		"enroll client: CA garble": func() error { _, err := hcrypto.EnrollClientTLS([]byte("garbage"), ""); return err },
		"enroll client: CA empty":  func() error { _, err := hcrypto.EnrollClientTLS(nil, ""); return err },
		"client: missing key":      func() error { _, err := hcrypto.LoadClientTLS(busCert, missing, p.CACertFile, ""); return err },
		"client: missing CA":       func() error { _, err := hcrypto.LoadClientTLS(busCert, busKey, missing, ""); return err },
		"client: CA not PEM":       func() error { _, err := hcrypto.LoadClientTLS(busCert, busKey, notPEM, ""); return err },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f(); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

// t7hCSR makes a PEM CSR for key.
func t7hCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "requester"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestSignCSR_KeyTypes: SignCSR accepts the key types Go's TLS stack
// accepts for client certificates, and each certificate it signs works on
// the mutual-TLS listener. It refuses P-224, which TLS does not offer.
func TestSignCSR_KeyTypes(t *testing.T) {
	p := enrpki.New(t)
	ca, err := hcrypto.ParseCA(p.CACertPEM, p.CAKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	gen := map[string]func() (crypto.Signer, error){
		"ECDSA P-256": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
		"ECDSA P-384": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
		"ECDSA P-521": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) },
		"RSA 2048":    func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) },
		"Ed25519": func() (crypto.Signer, error) {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			return k, err
		},
	}
	for name, g := range gen {
		t.Run(name, func(t *testing.T) {
			key, err := g()
			if err != nil {
				t.Fatal(err)
			}
			certPEM, err := ca.SignCSR(t7hCSR(t, key), "host-"+strings.ReplaceAll(name, " ", "-"), time.Hour)
			if err != nil {
				t.Fatalf("SignCSR: %v", err)
			}
			block, _ := pem.Decode(certPEM)
			cert := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
			certFile, keyFile := t7hWritePair(t, t.TempDir(), "bus", cert)
			client, err := hcrypto.LoadClientTLS(certFile, keyFile, p.CACertFile, "localhost")
			if err != nil {
				t.Fatalf("LoadClientTLS: %v", err)
			}
			srv, _, srvErr, cliErr := t7hHandshake(t, t7hServerCreds(t, p), client, "localhost")
			if srvErr != nil || cliErr != nil {
				t.Fatalf("handshake with the signed certificate: server %v, client %v", srvErr, cliErr)
			}
			if cn := t7hTLSState(t, srv).PeerCertificates[0].Subject.CommonName; !strings.HasPrefix(cn, "host-") {
				t.Errorf("peer CN %q", cn)
			}
		})
	}

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SignCSR(t7hCSR(t, p224), "host-p224", time.Hour); err == nil || !strings.Contains(err.Error(), "P-224") {
		t.Errorf("SignCSR with a P-224 key: %v, want an unsupported-curve error", err)
	}
}

// TestTokenSet_LenNil: a nil TokenSet (enrollment off) has no tokens.
func TestTokenSet_LenNil(t *testing.T) {
	var ts *hcrypto.TokenSet
	if ts.Len() != 0 {
		t.Errorf("nil TokenSet Len = %d", ts.Len())
	}
}
