// Package enrpki builds throwaway certificate authorities and certificates
// for the enrollment and mutual-TLS tests.
package enrpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PKI is a test CA with a server certificate for localhost, written to a
// temporary directory.
type PKI struct {
	Dir            string
	CACertFile     string
	CAKeyFile      string
	ServerCertFile string
	ServerKeyFile  string
	CACertPEM      []byte
	CAKeyPEM       []byte

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// New creates a CA (PKCS#8 key, as openssl writes) and a server certificate
// valid for localhost, 127.0.0.1 and ::1.
func New(t testing.TB) *PKI {
	t.Helper()
	dir := t.TempDir()
	p := &PKI{Dir: dir}

	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "hookmon test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	p.caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	p.caKey = caKey
	p.CACertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	p.CAKeyPEM = pkcs8PEM(t, caKey)
	p.CACertFile = write(t, dir, "ca.crt", p.CACertPEM)
	p.CAKeyFile = write(t, dir, "ca.key", p.CAKeyPEM)

	srvKey := newKey(t)
	srvTmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: "hookmon-server"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, p.caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	p.ServerCertFile = write(t, dir, "server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}))
	p.ServerKeyFile = write(t, dir, "server.key", pkcs8PEM(t, srvKey))
	return p
}

// ClientCert issues a client certificate from this CA directly, without
// enrollment, with the given CN and organizations.
func (p *PKI) ClientCert(t testing.TB, cn string, org ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn, Organization: org},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pkcs8PEM(t, key))
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	return cert
}

// CAPool returns a pool holding the CA certificate.
func (p *PKI) CAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	return pool
}

// ServerTLS returns a server TLS config with the server certificate that
// verifies client certificates against the CA as clientAuth says.
func (p *PKI) ServerTLS(t testing.TB, clientAuth tls.ClientAuthType) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.ServerCertFile, p.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		ClientCAs:    p.CAPool(),
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLS returns a client TLS config that trusts the CA, expects the
// server certificate for localhost, and presents cert if it is not nil.
func (p *PKI) ClientTLS(cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		RootCAs:    p.CAPool(),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

func pkcs8PEM(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func write(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
