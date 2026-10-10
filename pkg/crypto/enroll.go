package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// HostCertOrganization is the Organization the server writes into every bus
// certificate it signs. HostIDFromCert requires it, so a certificate the CA
// issued for another purpose, such as the server's own, is never taken as a
// host identity.
const HostCertOrganization = "hookmon-bus"

// DefaultCertValidity is how long a bus certificate is valid when the server
// config does not say.
const DefaultCertValidity = 365 * 24 * time.Hour

// GenerateAgentKeypair creates an ECDSA P-256 private key and a CSR for it,
// and returns both PEM-encoded. The CSR names the host, but that is only a
// courtesy: the server assigns the host ID and writes the certificate's
// subject itself.
func GenerateAgentKeypair(hostname string) (keyPEM, csrPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return keyPEM, csrPEM, nil
}

// CA is the certificate authority the server signs bus certificates with.
// The same CA certificate verifies client certificates on the mutual-TLS
// listener.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
}

// LoadCA reads a PEM CA certificate and its PEM private key from files.
func LoadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	return ParseCA(certPEM, keyPEM)
}

// ParseCA parses a PEM CA certificate and its PEM private key. The key may
// be PKCS#8, SEC 1 (EC) or PKCS#1 (RSA). It returns an error, never panics,
// on malformed input, on a certificate that is not a valid CA now, and on a
// key that does not belong to the certificate.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("CA cert: no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA cert: PEM type is %q, want CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("CA cert: not a CA certificate (basicConstraints CA:TRUE missing)")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA cert: key usage does not allow certificate signing")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("CA cert: not valid now (valid %s to %s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("CA key does not match the CA certificate")
	}

	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:     key,
	}, nil
}

// CertPEM returns the PEM-encoded CA certificate.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// SignCSR signs the public key in a PEM-encoded CSR and returns a PEM client
// certificate for hostID. The certificate's subject is CN=hostID,
// O=HostCertOrganization. Nothing else is taken from the CSR: its subject,
// DNS names, IP addresses and extensions are ignored, so a requester cannot
// choose its own identity. validity <= 0 means DefaultCertValidity; the
// certificate never outlives the CA.
func (ca *CA) SignCSR(csrPEM []byte, hostID string, validity time.Duration) ([]byte, error) {
	if hostID == "" {
		return nil, errors.New("host ID is required")
	}
	if validity <= 0 {
		validity = DefaultCertValidity
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("CSR: no PEM data found")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR: PEM type is %q, want CERTIFICATE REQUEST", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	if err := checkPublicKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostID,
			Organization: []string{HostCertOrganization},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// parsePrivateKey decodes a PEM private key in PKCS#8, SEC 1 or PKCS#1 form.
func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	return signer, nil
}

// checkPublicKey accepts the key types and sizes Go's TLS stack accepts for
// client certificates: ECDSA on P-256, P-384 or P-521, RSA of 2048 bits or
// more, and Ed25519.
func checkPublicKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key is %d bits, want at least 2048", k.N.BitLen())
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}
