package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/test/enrpki"
)

func enrParseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("not a PEM certificate: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func enrCA(t *testing.T) (*hcrypto.CA, *enrpki.PKI) {
	t.Helper()
	p := enrpki.New(t)
	ca, err := hcrypto.ParseCA(p.CACertPEM, p.CAKeyPEM)
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	return ca, p
}

func TestSignCSR_Good(t *testing.T) {
	ca, p := enrCA(t)
	keyPEM, csrPEM, err := hcrypto.GenerateAgentKeypair("web-01")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	hostID := uuid.New().String()

	certPEM, err := ca.SignCSR(csrPEM, hostID, time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert := enrParseCertPEM(t, certPEM)

	if cert.Subject.CommonName != hostID {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, hostID)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != hcrypto.HostCertOrganization {
		t.Errorf("Organization: got %q", cert.Subject.Organization)
	}
	if cert.IsCA {
		t.Error("issued certificate is a CA")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage: got %v, want client auth only", cert.ExtKeyUsage)
	}
	if got := cert.NotAfter.Sub(time.Now()); got > time.Hour+time.Minute || got < 50*time.Minute {
		t.Errorf("validity: expires in %v, want about 1h", got)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     p.CAPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued certificate does not verify against the CA: %v", err)
	}

	// The certificate is for the bus's key.
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse bus key: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("certificate public key is not the CSR's")
	}

	got, err := hcrypto.HostIDFromCert(cert)
	if err != nil || got != hostID {
		t.Errorf("HostIDFromCert: got (%q, %v), want %q", got, err, hostID)
	}

	// The CA certificate handed back to buses is the one loaded.
	if !strings.Contains(string(ca.CertPEM()), "BEGIN CERTIFICATE") ||
		!enrParseCertPEM(t, ca.CertPEM()).Equal(enrParseCertPEM(t, p.CACertPEM)) {
		t.Error("CertPEM does not return the CA certificate")
	}
}

// TestSignCSR_ServerAssignsIdentity sends a CSR that asks for another host's
// ID, the bus organization, DNS and IP names. Only the public key may be
// used: the CN must be the server's choice and no names may be copied.
func TestSignCSR_ServerAssignsIdentity(t *testing.T) {
	ca, _ := enrCA(t)
	victim := uuid.New().String()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: victim, Organization: []string{hcrypto.HostCertOrganization, "admins"}},
		DNSNames:    []string{"hookmon-server", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	assigned := uuid.New().String()
	certPEM, err := ca.SignCSR(csrPEM, assigned, 0)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert := enrParseCertPEM(t, certPEM)
	if cert.Subject.CommonName != assigned {
		t.Errorf("CN: got %q, want the server-assigned %q (requested %q)", cert.Subject.CommonName, assigned, victim)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != hcrypto.HostCertOrganization {
		t.Errorf("Organization copied from CSR: %q", cert.Subject.Organization)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Errorf("names copied from CSR: DNS %v, IP %v", cert.DNSNames, cert.IPAddresses)
	}
	// Zero validity means the default, capped at the CA's own expiry
	// (the test CA lasts a day).
	if cert.NotAfter.After(enrParseCertPEM(t, ca.CertPEM()).NotAfter) {
		t.Errorf("certificate outlives the CA: %v", cert.NotAfter)
	}
}

func TestSignCSR_MalformedCSR(t *testing.T) {
	ca, _ := enrCA(t)
	_, goodCSR, err := hcrypto.GenerateAgentKeypair("web-01")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(goodCSR)

	// Flip a byte inside the signature so the CSR parses but does not verify.
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-5] ^= 0xff

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"not PEM":        []byte("this is not a CSR"),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"garbage DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x03, 0x01, 0x02}}),
		"bad signature":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}),
		"RSA 1024 key":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakDER}),
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			if cert, err := ca.SignCSR(csr, uuid.New().String(), 0); err == nil {
				t.Fatalf("SignCSR accepted a malformed CSR and returned %q", cert)
			}
		})
	}

	if _, err := ca.SignCSR(goodCSR, "", 0); err == nil {
		t.Error("SignCSR accepted an empty host ID")
	}
}

func TestParseCA_Malformed(t *testing.T) {
	p := enrpki.New(t)
	other := enrpki.New(t)

	// A certificate that is not a CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// An expired CA.
	expTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(8),
		Subject:               pkix.Name{CommonName: "expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	expDER, err := x509.CreateCertificate(rand.Reader, expTmpl, expTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	expPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expDER})

	cases := []struct {
		name          string
		cert, keyData []byte
	}{
		{"empty cert", nil, p.CAKeyPEM},
		{"cert not PEM", []byte("garbage"), p.CAKeyPEM},
		{"cert wrong PEM type", p.CAKeyPEM, p.CAKeyPEM},
		{"cert garbage DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), p.CAKeyPEM},
		{"cert not a CA", leafPEM, leafKeyPEM},
		{"cert expired", expPEM, leafKeyPEM},
		{"empty key", p.CACertPEM, nil},
		{"key not PEM", p.CACertPEM, []byte("garbage")},
		{"key wrong PEM type", p.CACertPEM, p.CACertPEM},
		{"key garbage DER", p.CACertPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"key garbage EC DER", p.CACertPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"key of another CA", p.CACertPEM, other.CAKeyPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hcrypto.ParseCA(tc.cert, tc.keyData); err == nil {
				t.Fatal("ParseCA accepted malformed input")
			}
		})
	}

	if _, err := hcrypto.LoadCA(p.Dir+"/missing.crt", p.CAKeyFile); err == nil {
		t.Error("LoadCA accepted a missing certificate file")
	}
	if _, err := hcrypto.LoadCA(p.CACertFile, p.Dir+"/missing.key"); err == nil {
		t.Error("LoadCA accepted a missing key file")
	}
	if _, err := hcrypto.LoadCA(p.CACertFile, p.CAKeyFile); err != nil {
		t.Errorf("LoadCA: %v", err)
	}
}

// TestParseCA_KeyFormats checks the CA key may be SEC 1 EC or PKCS#1 RSA as
// well as the PKCS#8 that enrpki writes.
func TestParseCA_KeyFormats(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	for name, kc := range map[string]struct {
		pub    any
		signer any
		keyPEM []byte
	}{
		"SEC 1 EC":   {&ecKey.PublicKey, ecKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})},
		"PKCS#1 RSA": {&rsaKey.PublicKey, rsaKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "CA " + name},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				KeyUsage:              x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kc.pub, kc.signer)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := hcrypto.ParseCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), kc.keyPEM)
			if err != nil {
				t.Fatalf("ParseCA: %v", err)
			}
			_, csrPEM, err := hcrypto.GenerateAgentKeypair("h")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ca.SignCSR(csrPEM, uuid.New().String(), 0); err != nil {
				t.Fatalf("SignCSR: %v", err)
			}
		})
	}
}
