package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// LoadServerTLS loads TLS credentials for the gRPC server with mutual TLS.
func LoadServerTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsCfg), nil
}

// LoadEnrollServerTLS loads TLS credentials for the enrollment listener.
// The server authenticates itself with its certificate; clients present no
// certificate, since a bus enrolls to get one. Only the Enroll RPC is served
// there, and it requires an enrollment token.
func LoadEnrollServerTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// LoadHTTPServerTLS returns the TLS config for the REST API and dashboard
// listener: the server certificate, and no client certificate, because
// browsers and API clients authenticate with a token instead. TLS 1.2 is the
// minimum, since browsers reach this listener.
func LoadHTTPServerTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// EnrollClientTLS returns TLS credentials for a bus enrolling: it verifies
// the server against caPEM and presents no client certificate. An empty
// serverName means the host in the dial address.
func EnrollClientTLS(caPEM []byte, serverName string) (credentials.TransportCredentials, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs:    caPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}), nil
}

// LoadClientTLS loads TLS credentials for the gRPC agent client with mutual TLS.
func LoadClientTLS(certFile, keyFile, caFile, serverName string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsCfg), nil
}

// LoadInsecureClientTLS returns TLS credentials that skip server verification.
// Use only for development/testing.
func LoadInsecureClientTLS() credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
}
